# When the cycle stalls

Symptoms and fixes:

| Symptom                              | Likely cause                                              | Fix                                                                       |
| ------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------- |
| Can't think of the next test         | You've drifted into speculation                           | Re-read the agreed behavior list; pick the next item verbatim             |
| Test passes immediately when written | Implementation already covers it, or the test is too weak | Strengthen the assertion or skip — don't keep a test that never fails     |
| GREEN step balloons past ~20 lines   | The behavior is too coarse                                | Revert, split the behavior into smaller ones, restart                     |
| Refactor breaks tests                | Tests were coupled to implementation                      | Fix the tests to assert through the public interface, then refactor again |
| Many tests, no production code yet   | Horizontal slicing                                        | Stop. Delete the speculative tests. Restart with one test at a time       |
