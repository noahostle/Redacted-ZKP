
##Notice

When cloning the repository, it is normal for it to hang on 'Resolving Deltas'.
This is because it is downloading the large circuit file (zkp_rsa/build/ circuit_final.zkey and zk_attest.r1cs) in the background.
Please allow up to a few minutes for this accounting for file size and internet speed.




##(Internal Use) Updating Repo


Dont edit the report here directly.

Edit the redacted-report repo separately and commit your changes separately.

Then, set the 'Report' submodule to point to the most recent redacted-report commit by doing in the redacted-zkp directory;

cd Report
git pull (or git submodule update --init)

cd ..
git add Report
git commit -m "Refreshed report link"
git push
