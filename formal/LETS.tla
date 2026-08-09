------------------------------- MODULE LETS -------------------------------
EXTENDS Integers, FiniteSets, Naturals, Sequences, TLC

(***************************************************************************
Finite specification of the LETS escrow/transfer/replay kernel.  This model
tracks scalar rights; the executable implementation applies the equation per
resource-vector dimension.  The checked Python refinement model lives in
formal/model_checker.py.  Neither a finite TLC run nor that bounded search is
a proof for arbitrary configurations.
***************************************************************************)

CONSTANTS Wardens, InitialShare, MaxTransfers, MaxReceipts

ASSUME /\ Cardinality(Wardens) >= 2
       /\ InitialShare \in [Wardens -> Nat]
       /\ MaxTransfers \in Nat \ {0}
       /\ MaxReceipts \in Nat \ {0}

RECURSIVE PairSum(_)
PairSum(S) ==
    IF S = {} THEN 0
    ELSE LET pair == CHOOSE item \in S : TRUE
         IN pair[2] + PairSum(S \ {pair})

FunctionSum(function, domain) == PairSum({<<item, function[item]>> : item \in domain})

Budget == FunctionSum(InitialShare, Wardens)

UniformInitialShare == [w \in Wardens |-> 1]

VARIABLES pool, leased, consumed, transfers, receipts, claims, watermark,
          nextTransfer, nextReceipt

vars == <<pool, leased, consumed, transfers, receipts, claims, watermark,
          nextTransfer, nextReceipt>>

TransferStates == {"PREPARED", "ACCEPTED", "FINALIZED"}

Init ==
    /\ pool = InitialShare
    /\ leased = [w \in Wardens |-> 0]
    /\ consumed = 0
    /\ transfers = <<>>
    /\ receipts = <<>>
    /\ claims = {}
    /\ watermark = [w \in Wardens |-> 0]
    /\ nextTransfer = 1
    /\ nextReceipt = 1

IssueRoot(w) ==
    /\ pool[w] > 0
    /\ pool' = [pool EXCEPT ![w] = @ - 1]
    /\ leased' = [leased EXCEPT ![w] = @ + 1]
    /\ UNCHANGED <<consumed, transfers, receipts, claims, watermark,
                    nextTransfer, nextReceipt>>

Authorize(w) ==
    /\ leased[w] > 0
    /\ Len(receipts) < MaxReceipts
    /\ leased' = [leased EXCEPT ![w] = @ - 1]
    /\ consumed' = consumed + 1
    /\ receipts' = Append(receipts,
                           [id |-> nextReceipt, warden |-> w,
                            sequence |-> nextReceipt, nonce |-> nextReceipt])
    /\ nextReceipt' = nextReceipt + 1
    /\ UNCHANGED <<pool, transfers, claims, watermark, nextTransfer>>

Prepare(source, target) ==
    /\ source # target
    /\ pool[source] > 0
    /\ Len(transfers) < MaxTransfers
    /\ pool' = [pool EXCEPT ![source] = @ - 1]
    /\ transfers' = Append(transfers,
                            [id |-> nextTransfer, source |-> source,
                             target |-> target, amount |-> 1,
                             state |-> "PREPARED"])
    /\ nextTransfer' = nextTransfer + 1
    /\ UNCHANGED <<leased, consumed, receipts, claims, watermark, nextReceipt>>

Accept(i) ==
    /\ i \in 1..Len(transfers)
    /\ transfers[i].state = "PREPARED"
    /\ pool' = [pool EXCEPT ![transfers[i].target] = @ + transfers[i].amount]
    /\ transfers' = [transfers EXCEPT ![i].state = "ACCEPTED"]
    /\ UNCHANGED <<leased, consumed, receipts, claims, watermark,
                    nextTransfer, nextReceipt>>

DuplicateAccept(i) ==
    /\ i \in 1..Len(transfers)
    /\ transfers[i].state \in {"ACCEPTED", "FINALIZED"}
    /\ UNCHANGED vars

Finalize(i) ==
    /\ i \in 1..Len(transfers)
    /\ transfers[i].state = "ACCEPTED"
    /\ transfers' = [transfers EXCEPT ![i].state = "FINALIZED"]
    /\ UNCHANGED <<pool, leased, consumed, receipts, claims, watermark,
                    nextTransfer, nextReceipt>>

Claim(i) ==
    /\ i \in 1..Len(receipts)
    /\ receipts[i].id \notin claims
    /\ receipts[i].sequence > watermark[receipts[i].warden]
    /\ claims' = claims \cup {receipts[i].id}
    /\ watermark' = [watermark EXCEPT
                       ![receipts[i].warden] = receipts[i].sequence]
    /\ UNCHANGED <<pool, leased, consumed, transfers, receipts,
                    nextTransfer, nextReceipt>>

DuplicateOrStaleClaim(i) ==
    /\ i \in 1..Len(receipts)
    /\ \/ receipts[i].id \in claims
       \/ receipts[i].sequence <= watermark[receipts[i].warden]
    /\ UNCHANGED vars

Next ==
    \/ \E w \in Wardens : IssueRoot(w)
    \/ \E w \in Wardens : Authorize(w)
    \/ \E source, target \in Wardens : Prepare(source, target)
    \/ \E i \in 1..Len(transfers) : Accept(i) \/ DuplicateAccept(i) \/ Finalize(i)
    \/ \E i \in 1..Len(receipts) : Claim(i) \/ DuplicateOrStaleClaim(i)

PreparedIndexes ==
    {i \in 1..Len(transfers) : transfers[i].state = "PREPARED"}

InFlight ==
    PairSum({<<i, transfers[i].amount>> : i \in PreparedIndexes})

TypeOK ==
    /\ pool \in [Wardens -> Nat]
    /\ leased \in [Wardens -> Nat]
    /\ consumed \in Nat
    /\ \A i \in 1..Len(transfers) :
          /\ transfers[i].source \in Wardens
          /\ transfers[i].target \in Wardens
          /\ transfers[i].source # transfers[i].target
          /\ transfers[i].amount \in Nat \ {0}
          /\ transfers[i].state \in TransferStates
    /\ claims \subseteq {receipts[i].id : i \in 1..Len(receipts)}
    /\ watermark \in [Wardens -> Nat]

Conservation ==
    FunctionSum(pool, Wardens)
    + FunctionSum(leased, Wardens)
    + consumed + InFlight = Budget

Spec == Init /\ [][Next]_vars

=============================================================================
