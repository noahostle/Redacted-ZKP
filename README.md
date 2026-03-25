Dont edit the report here directly.

Edit the redacted-report repo separately and commit your changes separately.

Then, set the 'Report' submodule to point to the most recent redacted-report commit by doing in the redacted-zkp directory;

cd Report
git pull

cd ..
git add Report
git commit -m "Refreshed report link"
git push
