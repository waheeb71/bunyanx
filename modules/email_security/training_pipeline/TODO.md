# TODO — Dataset Expansion & Model Performance Improvement

- [x] Improve extractor robustness in `build_bec_dataset_from_raw.py` to parse more raw emails from `F:\enterprise_ngfw\dataset`.

- [ ] Ensure outputs remain in `modules/email_security/training_pipeline/data/` and do not recreate unrelated files.
- [x] Run `python modules/email_security/training_pipeline/build_bec_dataset_from_raw.py`.

- [x] Verify `dataset_train.csv`, `dataset_val.csv`, `dataset_test.csv` total samples >= 3000.

- [ ] Verify class balance is stratified (inspect `dataset_build_report.json`).
- [ ] Retrain/evaluate model ONLY if existing scripts already exist; otherwise implement minimal training/eval consistent with repo runtime.
- [ ] Update TODO checkboxes as work completes.


