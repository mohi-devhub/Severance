| scenario | condition | exact path | fix edge | same answer across runs | hallucinated edges | failed runs |
|---|---|---|---|---|---|---|
| public_bucket | engine | 100% | 100% | 100% | 0% | 0/10 |
| public_bucket | llm_no_tools | 100% | 100% | 100% | 0% | 0/10 |
| escalation_chain | engine | 100% | 100% | 100% | 0% | 0/10 |
| escalation_chain | llm_no_tools | 100% | 0% | 100% | 0% | 0/10 |
| broker_policy | engine | 100% | 100% | 100% | 0% | 0/10 |
| broker_policy | llm_no_tools | 100% | 70% | 70% | 0% | 0/10 |
| exposed_secret | engine | 100% | 100% | 100% | 0% | 0/10 |
| exposed_secret | llm_no_tools | 100% | 100% | 100% | 0% | 0/10 |

Accuracy and stability use all attempted runs; failures count as misses. Hallucinated-edge rate uses valid answers only (— if none).
