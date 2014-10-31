

Below are steps for using it:
1. capture pcap on SGC blade.
2. filter SIP messages and export to txt file.
3. use the python script to calculate the latency.
    python read_time.py -d "C:\Company\SBG\Test_result\R14B\Logs\SBG-SCT-4401.1\" -a "access.txt" -c "core.txt" -r "res.txt"
