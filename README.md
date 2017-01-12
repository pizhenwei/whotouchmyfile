# whotouchmyfile
Try to find which process has edit config by kprobe.</br>

# Howto
1, install kernel header files</br>
	sudo apt-get install linux-headers-`uname -r`</br>

</br>
2, download code</br>
	git clone https://github.com/pacepi/whotouchmyfile.git</br>

</br>
3, build</br>
	cd whotouchmyfile</br>

</br>
4, run</br>
	sudo insmod probe.ko</br>

</br>
5, debug</br>
	echo "file_you_want_to_watch" > /proc/sys/kernel/who_touch_my_file</br>

</br>
6, check log</br>
	dmesg</br>
