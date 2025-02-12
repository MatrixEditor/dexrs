pub(crate) mod container;
pub(crate) mod file;
pub(crate) mod error;
pub(crate) mod structs;


pub(crate) type ArcMutex<T> = std::sync::Arc<std::sync::Mutex<T>>;


macro_rules! arc_mutex_get {
    ($value:expr) => {
        $value.lock().unwrap()
    };
}

pub(crate) use arc_mutex_get;