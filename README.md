Golang script to decode Homemate api call
=========================================

First thanks to @insertjokehere to help me to understand the last part of how to decrypt the network trafic between the Homemate application and the aws server.

# Fetch the primary key

You first need to download the Homemate apk file and extract it with apktool.

```
apktool d HomeMate_v4.2.3.300.com.apk -o HomeMate_v4.2.3.300.com
```

Then search for the key in the file.

```
grep vicenter_db_key HomeMate_v4.2.3.300.com/res/values/strings.xml
```

# Network capture


```
tshark -i ppp0 -f "port 10002" -w /tmp/homemate.pcap

tshark -r /tmp/homemate.pcap -q -z follow,ssl,raw,0 > tmp/raw.data
```

# Decrypt

Execute the script with the following parameters

```
-file=/tmp/raw.data -password="the primary key"
```


# Next step

Write a golang daemon to be able to use the homemate api to execute a scene


