

Below are steps for using it:
1. capture pcap on SGC blade.
2. filter SIP messages and export to txt file, and named with ¡°access.txt¡± and ¡°core.txt¡±.
3. make a new file ¡°res.txt¡± for scripts to record the result.
4. use the python script to calculate the latency.
     python read_time.py -d "C:\simon\Company\SBG\Test_result\R14B+\SCT\SBG-SCT-4401.1\" -a "access.txt" -c "core.txt" -r "res.txt"
