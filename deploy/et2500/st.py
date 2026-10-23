import json,subprocess,time
names="up_redirect up_kernel up_control up_no_session up_spoofed down_redirect down_too_big down_kernel up_policed down_policed nat_out nat_in nat_new nat_exhausted nat_no_mapping nat_unsupported nat_frag_miss nat_icmp_error ipoe_up_redirect ipoe_up_kernel ipoe_up_no_session ipoe_up_spoofed ipoe_down_redirect ipoe_up_unleased up6_redirect up6_kernel up6_control up6_spoofed down6_redirect down6_too_big".split()
def snap():
    d=json.loads(subprocess.check_output(["bpftool","-j","map","dump","name","pppoe_stats"]))
    out={}
    for e in d:
        k=e["key"]; k=int(k[0],16) if isinstance(k,list) else k
        out[names[k]]=sum((int.from_bytes(bytes(int(b,16) for b in x["value"]),"little") if isinstance(x["value"],list) else x["value"]) for x in e["values"])
    return out
a=snap(); time.sleep(5); b=snap()
for k in names:
    r=(b.get(k,0)-a.get(k,0))/5
    if r: print("%-16s %10.0f pps" % (k,r))
