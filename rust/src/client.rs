use math::FE;
use num::Zero;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct CtrId(u32);
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct TrId([u8;32]);

#[derive(Debug,Clone)]
pub struct Counter {
    id : CtrId,
    val : FE
}

pub struct EncryptedSeed(Vec<u8>);

pub struct TRData {
    tr_id : TrId,
    seed : EncryptedSeed,
    x : FE,
    counters: Vec<FE>,
}

pub struct TRState {
    data : TRData
}

pub struct CounterSet {
    counter_ids : Vec<CtrId>, // XXXX use strings??
    counters : Vec<Counter>, // XXXX use a hashmap.
    tr_states : Vec<TRState>,
}

pub struct CounterData {
    counter_ids : Vec<CtrId>,
    tr_data : Vec<TRData>
}



impl Counter {
    fn new(id : CtrId) -> Counter {
        Counter { id, val : FE::zero() }
    }
    pub fn inc(&mut self, v : u32) {
        self.val += FE::from(v);
    }
    pub fn dec(&mut self, v : u32) {
        self.val -= FE::from(v);
    }
}


impl CounterSet {
    pub fn new(counter_ids : Vec<CtrId>, tr_ids : Vec<TrId>) -> Self {
        // XXX
        let counters = Vec::new();
        let tr_states = Vec::new();
        CounterSet{ counter_ids, counters, tr_states }
    }

    pub fn ctr(&mut self, ctr_id : CtrId) -> Option<&mut Counter> {
        self.counters.iter_mut().find(|ctr| ctr.id == ctr_id)
    }

    pub fn finalize(self) -> CounterData {
        // XXXX
        CounterData { counter_ids : self.counter_ids,
                      tr_data :  Vec::new() }
    }
}

