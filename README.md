# Cross-Input Signature Aggregation (CISA)

CISA is a potential Bitcoin softfork that reduces transaction weight. The purpose of this repository is to collect thoughts and resources on signature aggregation schemes themselves and how they could be integrated into Bitcoin.

## Contents

- [Half Aggregation](#half-aggregation)
- [Sigagg Case Study: LN Channel Announcements](#sigagg-case-study-ln-channel-announcements)
- [Integration Into The Bitcoin Protocol](#integration-into-the-bitcoin-protocol)
  - [Cross-input-aggregation savings](#cross-input-aggregation-savings)
  - [Half Aggregation And Mempool Caching](#half-aggregation-and-mempool-caching)
  - [Half Aggregation And Reorgs](#half-aggregation-and-reorgs)
  - [Half Aggregation And Adaptor Signatures](#half-aggregation-and-adaptor-signatures)

## Half Aggregation

Half aggregation allows non-interactively aggregating a set of signatures into a single aggregate signature whose size is half of the size of the original signatures.

See [half-aggregation.mediawiki](half-aggregation.mediawiki) for a detailed description.
There is also a [recording of Implementing Half Aggregation in libsecp256k1-zkp](https://www.youtube.com/watch?v=Dns_9jaNPNk) with accompanying ["slides"](slides/2021-Q2-halfagg-impl.org).

## Sigagg Case Study: LN Channel Announcements

[Channel announcements messages](https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#the-channel_announcement-message) are gossiped in the Lightning Network to allow nodes to discover routes for payments.

To prove that a channel between a node with public key `node_1` and a node with public key `node_2` does exist, the announcement contains four signatures.
First, the announcement contains `node_signature_1` and `node_signature_2` which are are signatures over the channel announcement message by `node_1` and `node_2` respectively.

The channel announcement also proves that the two keys `bitcoin_key_1` and `bitcoin_key_2` contained in the funding output of the funding transaction are owned by `node_1` and `node_2` respectively.
Therefore, it contains signature `bitcoin_signature_1` by `bitcoin_key_1` over `node_1` and `bitcoin_signature_2` by `bitcoin_key_2` over `node_2`.

1. Since `node_signature_1` and `node_signature_2` are signatures over the same message, one can use a scheme like [MuSig2](https://eprint.iacr.org/2020/1261.pdf) to replace both signatures with a single multisignature `node_signature` that has the same size as an individual signature.
2. In order to create a channel announcement message, both nodes need to cooperate.
   Therefore, they can interactively fully aggregate the three signatures into a single aggregate signature.
3. Channel announcements are often sent in batches.
   Within a batch, the signatures of all channel announcements can be non-interactively half aggregated since this does not require the communication with the nodes.
   Each channel announcement signature is thus reduced to a half-aggregated signature which is half the size of the original signature.

As a result, starting from four signatures (256 bytes) which make up about 60% of a channel announcement today are aggregated into one half signature (32 bytes for a large batch).

Of course, variations of above recipe are possible.
For example, if one wants to avoid full aggregation for simplicity's sake, the four signatures in an announcement can just be half aggregated to reduce them to the size of 2.5 signatures.

## Integration Into The Bitcoin Protocol

Since the verification algorithm for half and fully aggregated signatures differs from BIP 340 Schnorr Signature verification, nodes can not simply start to produce and verify aggregated signatures.
This would result in a chain split.

Taproot & Tapscript provide multiple upgrade paths:
- **Redefine `OP_SUCCESS` to `OP_CHECKAGGSIG`:**
    As pointed out in [this post to the bitcoin-dev mailing list](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-March/015838.html), an `OP_CHECKAGGSIG` appearing within a script that includes `OP_SUCCESS` can result in a chain split.
    That's because `OP_CHECKAGGSIG` does not actually verify the signature, but puts the public key in some datastructure against which the aggregate signature is only verified in the end - after having encountered all `OP_CHECKAGGSIG`.
    While one node sees `OP_SUCCESS OP_CHECKSIGADD`, a node with another upgrade - supposedly a softfork - may see `OP_DOPE OP_CHECKSIGADD`.
    Since they disagree how to verify the aggregate signature, they will disagree on the verification result which results in a chainsplit.
    Hence, `OP_CHECKAGGSIG` can't be used in a scripting system with `OP_SUCCESS`.
    The same argument holds for the attempt to add aggregate signatures via Tapscript's key version.
- **Define new leaf version to replace tapscript:** If the new scripting system has `OP_SUCCESS` then this does not solve the problem.
- **Define new SegWit version:**
    It is possible to define a new SegWit version that is a copy of Taproot & Tapscript with the exception that all keyspend signatures are allowed to be aggregated.
    However, keyspends can not be aggregated with other SegWit versions.

Assume that a new SegWit version is defined to deploy aggregate signatures by copying Taproot and Tapscript and allowing only keyspends to be aggregated.
This would be limiting.
For example, a spending policy `(pk(A) and pk(B)) or (pk(A) and older(N))` would usually be instantiated in Taproot by aggregating keys A and B to create a keypath spend and appending a script path for `(pk(A) and older(N))`.
It wouldn't be possible to aggregate the signature if the second spending path is used.

This [bitcoin-dev post](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-July/016249.html) shows that this limitation is indeed unnecessary by introducing Generalized Taproot, a.k.a. g'root  (see also [this post](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-October/016461.html) for a summary).
Essentially, instead of requiring that each leaf of the taproot merkle tree is a script, in g'root leafs can consist of both a public key and a script.
In order to use such a spending path, a signature for the public key must be provided, as well as the inputs to satisfy the script.
This means that the public key is moved out of the scripting system, leaving it unencumbered by `OP_SUCCESS` and other potentially dangerous Tapscript components.
Hence, signatures for these public keys _can_ be aggregated.

Consider the example policy `(pk(A) and pk(B)) or (pk(A) and older(N))` from above.
In g'root the root key `keyagg((pk(A), pk(B)))` commits via taproot tweaking to a spending condition consisting of public key `pk(A)` and script `older(N)`.
In order to spend with the latter path, the script must be satisfied and an _aggregated_ signature for `pk(A)` must exist.

The [Entroot](https://gist.github.com/sipa/ca1502f8465d0d5032d9dd2465f32603) proposal is a slightly improved version of g'root that integrates Graftroot.
One of the main appeals is that Entroot is "remarkably elegant" because the validation rules of Entroot are rather simple for the capabilities it enables.


### Cross-input Aggregation Savings

See [savings.org](savings.org).

### Half Aggregation And Mempool Caching

As mentioned [on bitcoin-dev](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-May/014308.html) nodes accepting a transaction with a half aggregate signature `(s, R_1, ..., R_n)` to their mempool would not throw it away or aggregate it with other signatures.
Instead, they keep the signature and when a block with block-wide aggregate signature `(s', R'_1, ..., R'_n')` arrives they can subtract `s` from `s'` and remove `R_1, ..., R_n`, from the block-wide aggregate signature before verifying it.
As a result, the nodes skip what they have already verified.

### Half Aggregation And Reorgs

Assume there is a transaction `X` with half aggregate signature `S0 = (s0, R_1, ..., R_n)`.
The transaction is contained in chain `C1` and therefore there exists a block with a signature `S1` that half aggregates all signatures in the block.
Since `s0` is aggregated into `S1`, it is not retrievable from the block.

Now there happens to be a reorganization from chain `C1` to chain `C2`.
There are the following two cases where half aggregation affects the reorganization.

1. Transaction `X` is contained in both chain `C1` and `C2`.
   Let `S2` be the block-wide half aggregate signature of the block in `C2` that conatains `X`.
   In general `S1 != S2`, so the whole half-aggregate signature `S2` must be verified, including the contribution of `X` despite having it verified already.
   If `s0` was kept, it could be subtracted from `S2`.
   This is in contrast to ordinary signatures, which do not have to be re-verified in a reorg.
2. Transaction `X` is contained in `C1` but not in `C2`.
   Because we can't recover `s0`, we can't broadcast transaction `X`, nor can we build a block that includes it.
   Hence, we can't meaningfully put `X` back into the mempool.

Both cases would indicate that it is beneficial to keep `s0` even though the transaction is included in the best chain.
Only when the transaction is buried so deep that reorgs can be ruled out, the value `s0` can be discarded.
This approach is certainly not fully satisfying.

Another solution for case 2. is to have the participants of the transaction (such as sender and receiver) rebroadcast the transaction.
But this may have privacy issues.

### Half Aggregation And Adaptor Signatures

Half aggregation prevents using adaptor signatures ([stackexchange](https://bitcoin.stackexchange.com/questions/107196/why-does-blockwide-signature-aggregation-prevent-adaptor-signatures)).
However, a new SegWit version as outlined in section [Integration Into The Bitcoin Protocol](#integration-into-the-bitcoin-protocol) would keep signatures inside Tapscript unaggregatable.
Hence, protocols using adaptor signatures can be instantiated by having adaptor signatures only appear inside Tapscript.

This should not be any less efficient in g'root if the output can be spend directly with a script, i.e., without showing a merkle proof.
However, since this is not a normal keypath spend and explicitly unaggregatable, such a spend will stick out from other transactions.
It is an open question if this actually affects protocols built on adaptor signatures.
In other words, can such protocols can be instantiated with a Tapscript spending path for the adaptor signature but without having to use actually use that path - at least in the cooperative case?
