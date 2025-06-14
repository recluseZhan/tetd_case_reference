This is an example of TETD agnet. Two TDs are used in AE: tetd_td and normal_td. Use the following commands to operate TD:

```
## Check TD status
virsh list --all
## Power on
virsh start tetd_td
virsh start normal_td
## Enter TD
virsh console tetd_td
virsh console normal_td
## Power off
virsh destroy tetd_td
virsh destroy normal_td
```

The agent contains TD_Reader tool and signature tool. Operation steps:
Step 1: Power on TD.
Step 2: Use the test.sh script in the tetd directory in tetd_td to enable the agent.
Step 3: Use the test.sh script in the tetd directory in normal_td to view the value passed by TETD.
