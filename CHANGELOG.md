# `v2.2.1`

- Change the repository organisation to `eclipse-biscuit` (#175) (Korbik)
- Support for root key ID (#151, #154) (Steven E. Harris)
- Add `SetContext` on `Builder` and `GetContext` on `Biscuit` (#153) (Benoit12345)
- Fix `deny` policy grammar (#157) (Collignon-Ducret Rémi)
- Fix panics on byte-array terms and `Set.Equal` in `datalog` (#185) (Antonio Ojea)
- Fix goroutine leak in `datalog` rule evaluation (#189) (Johann Queuniet)
- Mitigate `datalog` world timeout limitations (#181) (Johann Queuniet)
- CI and test improvements (#132, #133, #183, #184, #187) (Yaron Sheffer, Antonio Ojea)
