pub mod file;
pub mod meta;

use super::helpers::{
    BlockFutureResult, InfallibleFuture, IoVector, IoVectorMut, ThreadBound, Tristate,
};
use file::{Qcow2Queue, Qcow2State};
use super::node::{
    ChangeGraphStep, IoQueue, IoQueueDriverData, Node, NodeBasicInfo, NodeCacheConfig, NodeConfig,
    NodeConfigOrReference, NodeDriverData, NodeLimits, NodePerm, NodePermPair, NodeUser,
    NodeUserBuilder,
};

use super::BlockResult;
use super::BlockError;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex};

pub struct MutData {
    file: Arc<NodeUser>,
    backing: Option<Arc<NodeUser>>,

    drain_queue: ThreadBound<IoQueue>,
    state: Arc<Qcow2State>,

    pre_reopen_file: Option<Arc<NodeUser>>,
    pre_reopen_backing: Option<Option<Arc<NodeUser>>>,

    pre_reopen_drain_queue: Option<ThreadBound<IoQueue>>,
    pre_reopen_state: Option<Arc<Qcow2State>>,
}

pub struct Data {
    mut_data: Arc<Mutex<MutData>>,
}

pub struct Queue {
    file: Qcow2Queue,
    mut_data: Arc<Mutex<MutData>>,

    pre_reopen_file: Option<Qcow2Queue>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub file: NodeConfigOrReference,
    #[serde(default, skip_serializing_if = "Tristate::skip_serializing")]
    pub backing: Tristate<NodeConfigOrReference>,
}

impl Config {
    #[allow(clippy::ptr_arg)]
    pub fn split_tree(&mut self, vec: &mut Vec<NodeConfig>) -> BlockResult<()> {
        self.file.split_tree(vec)?;
        if let Tristate::Some(backing) = &mut self.backing {
            backing.split_tree(vec)?;
        }
        Ok(())
    }
}

impl Data {
    pub async fn new(
        node_name: &str,
        opts: Config,
        read_only: bool,
        _cache: &NodeCacheConfig,
    ) -> BlockResult<Box<Self>> {
        let data = MutData::new(node_name, opts, read_only).await?;
        Ok(Box::new(Data {
            mut_data: Arc::new(Mutex::new(data)),
        }))
    }
}

impl MutData {
    pub async fn new(node_name: &str, opts: Config, read_only: bool) -> BlockResult<Self> {
        let mut file_user = NodeUser::builder(node_name, "file")
            .require(NodePerm::ConsistentRead)
            .block(NodePerm::Write)
            .block(NodePerm::Resize);
        if !read_only {
            file_user = file_user.require(NodePerm::Write).require(NodePerm::Resize);
        }

        let file = opts.file.lookup()?.add_user(file_user).await?;
        let state = Qcow2State::new(&file, read_only).await?;

        let backing = match opts.backing {
            Tristate::NotSpecified => {
                if let Some(filename) = state.header_backing_filename().await {
                    return Err(format!(
                        "Implicit backing files not supported yet (image header specifies: \"{}\"{})",
                        filename,
                        state.header_backing_format().await
                            .map(|fmt| format!(" (format: {})", fmt))
                            .unwrap_or_else(|| "".into())
                    )
                    .into());
                } else {
                    None
                }
            }

            Tristate::Null => None,

            Tristate::Some(node) => {
                let backing_user = NodeUser::builder(node_name, "backing")
                    .require(NodePerm::ConsistentRead)
                    .block(NodePerm::Resize);

                Some(node.lookup()?.add_user(backing_user).await?)
            }
        };

        let drain_queue = file.new_queue()?;
        // Safe because reopen, quiesce, and node drop functions always run in the main thread
        let drain_queue = unsafe { ThreadBound::new_unsafe(drain_queue) };

        Ok(MutData {
            file,
            backing,
            drain_queue,
            state: Arc::new(state),
            pre_reopen_file: None,
            pre_reopen_backing: None,
            pre_reopen_drain_queue: None,
            pre_reopen_state: None,
        })
    }
}

#[async_trait]
impl NodeDriverData for Data {
    async fn get_basic_info(&self) -> BlockResult<NodeBasicInfo> {
        let data = self.mut_data.lock().unwrap();
        Ok(NodeBasicInfo {
            limits: NodeLimits {
                size: AtomicU64::new(data.state.virtual_size()),
                request_alignment: AtomicUsize::new(data.file.node().request_align()),
                memory_alignment: AtomicUsize::new(data.file.node().mem_align()),
                enforced_memory_alignment: AtomicUsize::new(1),
            },
        })
    }

    fn drain_caches(&mut self) -> InfallibleFuture {
        Box::pin(async move {
            let (state, drain_queue) = {
                let data = self.mut_data.lock().unwrap();
                let drain_queue = data.drain_queue.take().unwrap();
                (Arc::clone(&data.state), drain_queue)
            };
            if let Err(err) = state.flush_caches(&drain_queue).await {
                // TODO: Should be an event
                eprintln!("ERROR: Failed to flush qcow2 metadata cache: {}", err);
            }
        })
    }

    fn new_queue(&self) -> BlockResult<Box<dyn IoQueueDriverData>> {
        let data = self.mut_data.lock().unwrap();
        Ok(Box::new(Queue {
            file: data.state.new_queue(&data.file, &data.backing)?,
            mut_data: Arc::clone(&self.mut_data),
            pre_reopen_file: None,
        }))
    }

    fn get_children(&self) -> Vec<Arc<Node>> {
        let data = self.mut_data.lock().unwrap();
        let file = Arc::clone(data.file.node());
        vec![file]
    }

    fn get_children_after_reopen(&self, opts: &NodeConfig) -> BlockResult<Vec<Arc<Node>>> {
        let opts: &Config = (&opts.driver).try_into()?;
        let file = opts.file.lookup()?;
        Ok(vec![file])
    }

    fn quiesce(&self) -> InfallibleFuture {
        Box::pin(async move {
            let (state, drain_queue) = {
                let data = self.mut_data.lock().unwrap();
                let drain_queue = data.drain_queue.take().unwrap();
                (Arc::clone(&data.state), drain_queue)
            };
            if let Err(err) = state.flush_caches(&drain_queue).await {
                // TODO: Should be an event
                // TODO: Should this prevent a potential follow-up reopen from succeeding?
                eprintln!("ERROR: Failed to flush qcow2 metadata cache: {}", err);
            }

            let mut data = self.mut_data.lock().unwrap();
            // Safe because reopen, quiesce, and node drop functions always run in the main thread
            data.drain_queue = unsafe { ThreadBound::new_unsafe(drain_queue) };
        })
    }

    fn reopen_change_graph<'a>(
        &'a self,
        opts: &'a NodeConfig,
        perms: NodePermPair,
        read_only: bool,
        step: ChangeGraphStep,
    ) -> BlockFutureResult<'a, ()> {
        Box::pin(async move {
            let node_name = &opts.node_name;
            let opts: &Config = (&opts.driver).try_into()?;
            let new_file = opts.file.lookup()?;
            let new_backing = match &opts.backing {
                // `NotSpecified` will be rejected by `do_reopen()` if the new state (metadata)
                // specifies a backing filename
                Tristate::NotSpecified => None,
                Tristate::Null => None,
                Tristate::Some(node) => Some(node.lookup()?),
            };
            let mut data = self.mut_data.lock().unwrap();

            match step {
                ChangeGraphStep::Release => {
                    data.file
                        .set_perms_in_reopen_change_graph(NodePermPair::default())?;
                }

                ChangeGraphStep::Acquire => {
                    let mut file_user = NodeUserBuilder::from(data.file.as_ref())
                        .require(NodePerm::ConsistentRead)
                        .block(NodePerm::Write)
                        .block(NodePerm::Resize);
                    if !read_only {
                        file_user = file_user.require(NodePerm::Write).require(NodePerm::Resize);
                    }

                    let new_file = new_file.add_user_in_reopen_change_graph(file_user)?;

                    let mut backing_user = NodeUser::builder(node_name, "backing")
                        .require(NodePerm::ConsistentRead)
                        .block(NodePerm::Resize);
                    if perms.blocks(NodePerm::Write) {
                        backing_user = backing_user.block(NodePerm::Write)
                    };

                    let new_backing = new_backing
                        .map(|nb| nb.add_user_in_reopen_change_graph(backing_user))
                        .transpose()?;

                    let new_drain_queue = new_file.new_queue()?;
                    // Safe because reopen, quiesce, and node drop functions always run in the main thread
                    let new_drain_queue = unsafe { ThreadBound::new_unsafe(new_drain_queue) };

                    let old_file = std::mem::replace(&mut data.file, new_file);
                    data.pre_reopen_file.replace(old_file);

                    let old_backing = std::mem::replace(&mut data.backing, new_backing);
                    data.pre_reopen_backing.replace(old_backing);

                    let old_drain_queue = std::mem::replace(&mut data.drain_queue, new_drain_queue);
                    data.pre_reopen_drain_queue.replace(old_drain_queue);
                }
            }

            Ok(())
        })
    }

    fn reopen_do(
        &self,
        opts: NodeConfig,
        _perms: NodePermPair,
        read_only: bool,
    ) -> BlockFutureResult<()> {
        Box::pin(async move {
            let opts: Config = opts.driver.try_into()?;

            let file = {
                let data = self.mut_data.lock().unwrap();
                // Make a reference that is independent of the mutex (so we do not have to keep
                // `self.mut_data` locked across the `await`)
                Arc::clone(&data.file)
            };
            let new_state = Qcow2State::new(&file, read_only).await?;
            if matches!(opts.backing, Tristate::NotSpecified) {
                if let Some(filename) = new_state.header_backing_filename().await {
                    return Err(format!(
                    "Implicit backing files not supported yet (image header specifies: \"{}\"{})",
                    filename,
                    new_state.header_backing_format().await
                        .map(|fmt| format!(" (format: {})", fmt))
                        .unwrap_or_else(|| "".into())
                )
                    .into());
                }
            }

            let mut data = self.mut_data.lock().unwrap();
            let old_state = std::mem::replace(&mut data.state, Arc::new(new_state));
            data.pre_reopen_state.replace(old_state);

            Ok(())
        })
    }

    fn reopen_clean(&self) {
        let mut data = self.mut_data.lock().unwrap();
        data.pre_reopen_drain_queue.take();
        data.pre_reopen_backing.take();
        data.pre_reopen_file.take();
        data.pre_reopen_state.take();
    }

    fn reopen_roll_back(&self) {
        let mut data = self.mut_data.lock().unwrap();
        if let Some(old_drain_queue) = data.pre_reopen_drain_queue.take() {
            data.drain_queue = old_drain_queue;
        }
        if let Some(old_state) = data.pre_reopen_state.take() {
            data.state = old_state;
        }
        if let Some(old_backing) = data.pre_reopen_backing.take() {
            data.backing = old_backing;
        }
        if let Some(old_file) = data.pre_reopen_file.take() {
            data.file = old_file;
        }
    }
}

impl IoQueueDriverData for Queue {
    fn readv<'a>(&'a self, bufv: IoVectorMut<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        Box::pin(self.file.read_at(bufv, offset))
    }

    fn writev<'a>(&'a self, bufv: IoVector<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        Box::pin(self.file.write_at(bufv, offset))
    }

    fn flush(&self) -> BlockFutureResult<'_, ()> {
        Box::pin(self.file.flush())
    }

    fn reopen_do(&mut self) -> BlockResult<()> {
        let data = self.mut_data.lock().unwrap();
        let new_file = data.state.new_queue(&data.file, &data.backing)?;
        let old_file = std::mem::replace(&mut self.file, new_file);
        self.pre_reopen_file.replace(old_file);

        Ok(())
    }

    fn reopen_clean(&mut self) {}

    fn reopen_roll_back(&mut self) {}
}
