struct BasicBlock<T>{
    start: u64,
    size: u64,
    next: (u64, Box<T>),
}
