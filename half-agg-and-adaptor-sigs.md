# Does cross-input half-aggregation affect adaptor signature protocols?

We assume that half-aggregation is only allowed to be applied to key spends, not to script spends.

# In the cooperative case, half-aggregation can add a half-roundtrip to the communication cost

To demonstrate this claim, let's look at an adaptor signature protocol, first without half-aggregation and then with half aggregation.

## Without half-aggregation

**Scenario**: Alice creates a coin that can be spent by either
1. Alice and Bob (key spend)
2. Alice after time T (script spend)

Alice wants to learn a secret if Bob spends the coin.

- Bob sends Alice an adaptor signature for path 1 over a transaction that sends all coins to Bob.
- Alice replies with a signature for path 1.
- Bob spends via path 1. Alice extracts the secret from the adaptor sig and Bob's real sig and is happy.

## With half-aggregation

**Scenario**: Alice creates a coin that can be spent by either
1. Alice and Bob (key spend)
2. Alice after time T (script spend)
3. Alice and Bob (script spend)

Alice wants to learn a secret if Bob spends the coin.

- Bob sends Alice an adaptor signature for path 3 over a transaction that sends all coins to Bob.
  Due to half-aggregation, path 1 can not be used for this: the signature could get randomized which would prevent extracting the secret.
- Alice replies with a signature for path 3.
- Bob could spend via path 3, but that would be more expensive than spending via path 1.
- Therefore, Bob sends Alice the secret directly
- ... and if Alice cooperates, she replies with a signature for path 1.

Thus, with half aggregation, the cooperative case requires more communication.

Note that there are adaptor signature protocols that are not affected by half aggregation.
In some sense, there are two types of adaptor signature interactions, one where Alice learns a secret from a transaction and one where Bob can create a transaction after learning a secret (for example, by making a lightning payment).
We have seen the former above and provide an example for the latter below to show that it is unaffected by half aggregation.
The standard scriptless script coinswap requires both types of adaptor signatures.

### Unaffected adaptor sig protocol

**Scenario**: Alice creates a coin that can be spent by either
1. Alice and Bob (key spend)
2. Alice after time T (script spend)

Bob wants to be able to spend the coin if he learns a secret.

Alice sends Bob an adaptor signature for path 1 over a transaction that sends all coins to Bob.
Using the secret adaptor that Bob later learns, Bob can extract the signature.
Once Bob learns the adaptor secret, for example, by making a Lightning payment, he can immediately spend the funding output via path 1.
