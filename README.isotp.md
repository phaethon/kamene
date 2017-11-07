Hardware Setup
--------------

###  Operating System Setup

1.  Download an Image\
    The latest Debian Linux image can be found at the website\
    `https://beagleboard.org/latest-images`. Choose the BeagleBone Black
    IoT version and download it.

        wget https://debian.beagleboard.org/images/bone-debian-8.7\
        -iot-armhf-2017-03-19-4gb.img.xz


    After the download, copy it to a with minimum 4 GB storage.

        xzcat bone-debian-8.7-iot-armhf-2017-03-19-4gb.img.xz | \
        sudo dd of=/dev/xvdj


2.  Enable WiFi\
    USB-WiFi dongles are well supported from Debian Linux. Login over on
    the and add the WiFi network credentials to the file
    `/var/lib/connman/wifi.config`. If a -WiFi dongle is not available,
    it’s also possible to share the host’s internet connection with the
    connection of the emulated over . A tutorial to share the host
    network connection can be found on this page:\
    `https://elementztechblog.wordpress.com/2014/12/22/sharing-internet -using-network-over-usb-in-beaglebone-black/`.\
    Login as root onto the :

        ssh debian@192.168.7.2
        sudo su


    Provide the WiFi login credentials to connman:

        echo "[service_home]
        Type = wifi
        Name = ssid
        Security = wpa
        Passphrase = xxxxxxxxxxxxx" \
        > /var/lib/connman/wifi.config


    Restart the connman service:

        systemctl restart connman.service


3.  Install Required Packages\
    This step is required to install all necessary software packages to
    continue with the modification of the device tree overlay.

        apt-get update
        apt-get -y upgrade
        exit
        git clone https://github.com/beagleboard/bb.org-overlays
        cd ./bb.org-overlays


    Verify the installed version to ensure that the is suitable for the
    downloaded overlays. Version 1.4.1 or higher is required.

        dtc --version


    Update the installed with an update script in the cloned repository.

        ./dtc-overlay.sh


    Compile all delivered files and install the onto the current system.
    Again, a delivered script simplifies this job.

        ./install.sh


    Now, the operating system and the device tree are ready
    for modifications.

### Dual-CAN Setup

1.  Create a CAN0 Overlay\
    Inside the folder, create a file with the content of the
    following listing.

        cd ~/bb.org-overlays/src/arm
        cat <<EOF > BB-CAN0-00A0.dts

        /dts-v1/;
        /plugin/;

        #include <dt-bindings/board/am335x-bbw-bbb-base.h>
        #include <dt-bindings/pinctrl/am33xx.h>

        / {
        	compatible = "ti,beaglebone", \
        	"ti,beaglebone-black", "ti,beaglebone-green";

        	/* identification */
        	part-number = "BB-CAN0";
        	version = "00A0";

        	/* state the resources this cape uses */
        	exclusive-use =
        	/* the pin header uses */
        	"P9.19", /* can0_rx */
        	"P9.20", /* can0_tx */
        	/* the hardware ip uses */
        	"dcan0";

        	fragment@0 {
        		target = <&am33xx_pinmux>;
        		__overlay__ {
        		 bb_dcan0_pins: pinmux_dcan0_pins {
        			pinctrl-single,pins = <
        			 0x178 0x12 /* d_can0_tx */
        			 0x17C 0x32 /* d_can0_rx */
        			 >;
        			};
        		};
        	};

        	fragment@1 {
        		target = <&dcan0>;
        		__overlay__ {
        		 status = "okay";
        		 pinctrl-names = "default";
        		 pinctrl-0 = <&bb_dcan0_pins>;
        		};
        	};
        };
        EOF


    Compile the generated file with the delivered Makefile from
    the repository.

        cd ../../
        make
        sudo make install


2.  Modify the Boot Device Tree Blob\
    Backup and decompile the current device tree blob.

        cp /boot/dtbs/4.4.54-ti-r93/am335x-boneblack.dtb ~/
        dtc -I dtb -O dts ~/am335x-boneblack.dtb \
        > ~/am335x-boneblack.dts


    To free the CAN0 pins of the , the I2C2 pins need to be disabled.
    This can be done by commenting out the appropriate lines in
    the file. Search for the pinmux\_i2c2\_pins section and save the
    modified file with a new name. The BeagleBone community uses the
    I2C2 peripheral module for the communication and identification of
    extension modules, so called capes. This modification disables the
    compatibility to any of these capes.

        vim am335x-boneblack.dts

        895 /* pinmux_i2c2_pins {
        896     pinctrl-single,pins = <0x178 0x33 0x17c 0x33>;
        897     linux,phandle = <0x35>;
        898     phandle = <0x35>;
        899 };*/

        : wq am335x-boneblack_new.dts


    Compile the modified file and replace the original file in the boot
    partition of the . Reboot the after the replacement.

        dtc -O dtb -o ~/am335x-boneblack_new.dtb -b 0 \
        ~/am335x-boneblack_new.dts

        cp ~/am335x-boneblack_new.dtb \
        /boot/dtbs/4.4.54-ti-r93/am335x-boneblack.dtb

        reboot


3.  Test the Dual-CAN Setup\
    Load the kernel modules and the overlays.

        sudo su
        modprobe can
        modprobe can-dev
        modprobe can-raw

        echo BB-CAN0 > /sys/devices/platform/bone_capemgr/slots
        echo BB-CAN1 > /sys/devices/platform/bone_capemgr/slots


    Check the output of the Capemanager if both interfaces have
    been loaded.

        cat /sys/devices/platform/bone_capemgr/slots

        0: PF----  -1
        1: PF----  -1
        2: PF----  -1
        3: PF----  -1
        4: P-O-L-   0 Override Board Name,00A0,Override Manuf,\
        BB-CAN0
        5: P-O-L-   1 Override Board Name,00A0,Override Manuf,\
        BB-CAN1


    If something went wrong, `dmesg` provides kernel messages to analyze
    the root of failure.

4.  Optional: Enable Dual-CAN Setup at Boot

        echo "modprobe can \
        modprobe can-dev \
        modprobe can-raw" >> /etc/modules

        echo "cape_enable=bone_capemgr.enable_partno= \
        BB-CAN0,BB-CAN1" >> /boot/uEnv.txt

        update-initramfs -u


###  Kernel Module Installation

A Linux kernel module can be downloaded from this website:
`https://github.com/ hartkopp/can-isotp.git`. The file `README.isotp` in
this repository provides all information and necessary steps for
downloading and building this kernel module. kernel modules should also
be added to the `/etc/modules` file, to load this modules automatically
at boot.

### CAN-Interface Setup

As final step to prepare the interfaces for use, these interfaces have
to be setup through some terminal commands. The bitrate can be chosen to
fit the bitrate of a bus under test.

    ip link set can0 up type can bitrate 500000
    ip link set can1 up type can bitrate 500000
    ifconfig can0 up
    ifconfig can1 up