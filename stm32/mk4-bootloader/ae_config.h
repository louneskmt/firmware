// autogenerated; see bootloader/keylayout.py

// For Mk4 systems only!

// bytes [16..84) of chip config area
#define AE_CHIP_CONFIG_1 { \
	0xe1, 0x00, 0x61, 0x00, 0x00, 0x00, 0x8f, 0x2d, 0x8f, 0x80,   \
	0x8f, 0x43, 0xaf, 0x80, 0x00, 0x43, 0x00, 0x43, 0x8f, 0x20,   \
	0xc3, 0x43, 0xc3, 0x43, 0xc3, 0x43, 0x00, 0x00, 0x00, 0x00,   \
	0x8f, 0x4d, 0x8f, 0x43, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,   \
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,   \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00,   \
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   \
}


// bytes [90..128) of chip config area
#define AE_CHIP_CONFIG_2 { \
	0x02, 0x15, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x5c, 0x00,   \
	0xbc, 0x01, 0xfc, 0x01, 0xbc, 0x01, 0x9c, 0x01, 0x9c, 0x01,   \
	0xd3, 0x03, 0xdc, 0x03, 0xdc, 0x03, 0xdc, 0x03, 0x3c, 0x00,   \
	0x3c, 0x00, 0xfc, 0x01, 0xdc, 0x01, 0x3c, 0x00   \
}


// key/slot usage and names
#define KEYNUM_pairing             	1
#define KEYNUM_pin_stretch         	2
#define KEYNUM_main_pin            	3
#define KEYNUM_pin_attempt         	4
#define KEYNUM_lastgood            	5
#define KEYNUM_match_count         	6
#define KEYNUM_joiner_key          	7
#define KEYNUM_long_secret         	8
#define KEYNUM_secret              	9
#define KEYNUM_check_secret        	10
#define KEYNUM_brickme             	13
#define KEYNUM_firmware            	14

/*

RevNum: 00006002  len=4
Chip type: atecc608
AES_Enable = 0x1
I2C_Enable = 0x0
GPIO Mode = 0x1
GPIO Default = 0x0
GPIO Detect (vs authout) = 0x0
GPIO SignalKey/KeyId = 0xe
I2C_Address(sic) = 0xe1
CountMatchKey = 0x6
CounterMatch enable = 1
ChipMode = 0x0

     Slot[0] = 0x0000 = SlotConfig(ReadKey=0, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=0, WriteConfig=0)=0x0000
KeyConfig[0] = 0x3c00 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=0, ReqAuth=0, AuthKey=0, PersistentDisable=0, RFU=0, X509id=0)=0x003c

     Slot[1] = 0x8f2d = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=1, WriteKey=13, WriteConfig=2)=0x2d8f
KeyConfig[1] = 0x5c00 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=1, ReqAuth=0, AuthKey=0, PersistentDisable=0, RFU=0, X509id=0)=0x005c

     Slot[2] = 0x8f80 = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=1, WriteKey=0, WriteConfig=8)=0x808f
KeyConfig[2] = 0xbc01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=0, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x01bc

     Slot[3] = 0x8f43 = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=1, WriteKey=3, WriteConfig=4)=0x438f
KeyConfig[3] = 0xfc01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=1, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x01fc

     Slot[4] = 0xaf80 = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=1, EncryptRead=0, IsSecret=1, WriteKey=0, WriteConfig=8)=0x80af
KeyConfig[4] = 0xbc01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=0, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x01bc

     Slot[5] = 0x0043 = SlotConfig(ReadKey=0, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=3, WriteConfig=4)=0x4300
KeyConfig[5] = 0x9c01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=0, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x019c

     Slot[6] = 0x0043 = SlotConfig(ReadKey=0, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=3, WriteConfig=4)=0x4300
KeyConfig[6] = 0x9c01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=0, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x019c

     Slot[7] = 0x8f20 = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=1, WriteKey=0, WriteConfig=2)=0x208f
KeyConfig[7] = 0xd303 = KeyConfig(Private=1, PubInfo=1, KeyType=4, Lockable=0, ReqRandom=1, ReqAuth=1, AuthKey=3, PersistentDisable=0, RFU=0, X509id=0)=0x03d3

     Slot[8] = 0xc343 = SlotConfig(ReadKey=3, NoMac=0, LimitedUse=0, EncryptRead=1, IsSecret=1, WriteKey=3, WriteConfig=4)=0x43c3
KeyConfig[8] = 0xdc03 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=1, ReqAuth=1, AuthKey=3, PersistentDisable=0, RFU=0, X509id=0)=0x03dc

     Slot[9] = 0xc343 = SlotConfig(ReadKey=3, NoMac=0, LimitedUse=0, EncryptRead=1, IsSecret=1, WriteKey=3, WriteConfig=4)=0x43c3
KeyConfig[9] = 0xdc03 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=1, ReqAuth=1, AuthKey=3, PersistentDisable=0, RFU=0, X509id=0)=0x03dc

     Slot[10] = 0xc343 = SlotConfig(ReadKey=3, NoMac=0, LimitedUse=0, EncryptRead=1, IsSecret=1, WriteKey=3, WriteConfig=4)=0x43c3
KeyConfig[10] = 0xdc03 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=1, ReqAuth=1, AuthKey=3, PersistentDisable=0, RFU=0, X509id=0)=0x03dc

     Slot[11] = 0x0000 = SlotConfig(ReadKey=0, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=0, WriteConfig=0)=0x0000
KeyConfig[11] = 0x3c00 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=0, ReqAuth=0, AuthKey=0, PersistentDisable=0, RFU=0, X509id=0)=0x003c

     Slot[12] = 0x0000 = SlotConfig(ReadKey=0, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=0, WriteConfig=0)=0x0000
KeyConfig[12] = 0x3c00 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=0, ReqAuth=0, AuthKey=0, PersistentDisable=0, RFU=0, X509id=0)=0x003c

     Slot[13] = 0x8f4d = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=1, WriteKey=13, WriteConfig=4)=0x4d8f
KeyConfig[13] = 0xfc01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=1, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x01fc

     Slot[14] = 0x8f43 = SlotConfig(ReadKey=15, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=1, WriteKey=3, WriteConfig=4)=0x438f
KeyConfig[14] = 0xdc01 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=0, ReqRandom=1, ReqAuth=1, AuthKey=1, PersistentDisable=0, RFU=0, X509id=0)=0x01dc

     Slot[15] = 0x0000 = SlotConfig(ReadKey=0, NoMac=0, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=0, WriteConfig=0)=0x0000
KeyConfig[15] = 0x3c00 = KeyConfig(Private=0, PubInfo=0, KeyType=7, Lockable=1, ReqRandom=0, ReqAuth=0, AuthKey=0, PersistentDisable=0, RFU=0, X509id=0)=0x003c

Counter[0]: ffffffff00000000  len=8
Counter[1]: ffffffff00000000  len=8
UseLock = 0x0
VolatileKeyPermission = 0x0
SecureBoot: 0000  len=2
KldfvLoc = 0xf0
KdflvStr: 0000  len=2
UserExtra = 0x0
UserExtraAdd = 0x0
LockValue = 0x55
LockConfig = 0x55
SlotLocked: ffff  len=2
ChipOptions: 0215  len=2
ChipOptions = ChipOptions(POSTEnable=0, IOProtKeyEnable=1, KDFAESEnable=0, mustbezero=0, ECDHProt=1, KDFProt=1, IOProtKey=1)=0x1502
X509format: 00000000  len=4

*/
