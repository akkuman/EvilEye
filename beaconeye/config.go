package beaconeye

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/akkuman/EvilEye/win32"
)

type ConfigShortItem struct {
	v    int16
	name string
}

func (c *ConfigShortItem) New(name string) ConfigItemIface {
	return &ConfigShortItem{name: name}
}

func (c *ConfigShortItem) Parse(r io.Reader, process ProcessScan) {
	c.v = ReadInt16(r)
}

func (c *ConfigShortItem) String() string {
	return fmt.Sprintf("%s: %d", c.name, c.v)
}

func (c *ConfigShortItem) ExpectedType() Type {
	return TypeShort
}

type ConfigIntegerItem struct {
	v    int32
	name string
}

func (c *ConfigIntegerItem) New(name string) ConfigItemIface {
	return &ConfigIntegerItem{name: name}
}

func (c *ConfigIntegerItem) Parse(r io.Reader, process ProcessScan) {
	c.v = ReadInt32(r)
}

func (c *ConfigIntegerItem) String() string {
	return fmt.Sprintf("%s: %d", c.name, c.v)
}

func (c *ConfigIntegerItem) ExpectedType() Type {
	return TypeInteger
}

type ConfigStringItem struct {
	v    string
	name string
}

func (c *ConfigStringItem) New(name string) ConfigItemIface {
	return &ConfigStringItem{name: name}
}

func (c *ConfigStringItem) Parse(r io.Reader, process ProcessScan) {
	var address uintptr
	size := process.pointerSize()
	data := make([]byte, size)
	r.Read(data)
	if size == 4 {
		address = uintptr(binary.LittleEndian.Uint32(data))
	} else {
		address = uintptr(binary.LittleEndian.Uint64(data))
	}
	c.v = c.readNullString(process, address)
}

func (c *ConfigStringItem) String() string {
	return fmt.Sprintf("%s: %s", c.name, c.v)
}

func (c *ConfigStringItem) ExpectedType() Type {
	return TypeBytes
}

func (c *ConfigStringItem) readNullString(process ProcessScan, address uintptr) string {
	var buf bytes.Buffer
	for {
		strChar, err := win32.NtReadVirtualMemory(process.Handle, win32.PVOID(address), 1)
		if err != nil {
			fmt.Printf("read byte error: %v\n", err)
		}
		address++
		if strChar[0] == 0 {
			break
		}
		buf.WriteByte(strChar[0])
	}
	return buf.String()
}

type ConfigProgramItem struct {
	name string
	v    string
}

func (c *ConfigProgramItem) New(name string) ConfigItemIface {
	return &ConfigProgramItem{name: name}
}

// TODO: parse config
func (c *ConfigProgramItem) Parse(r io.Reader, process ProcessScan) {
	size := process.pointerSize()
	data := make([]byte, size)
	var address uintptr
	if size == 4 {
		address = uintptr(binary.LittleEndian.Uint32(data))
	} else {
		address = uintptr(binary.LittleEndian.Uint64(data))
	}
	c.v = fmt.Sprintf("0x%x", address)
}

func (c *ConfigProgramItem) String() string {
	return fmt.Sprintf("%v: %v", c.name, c.v)
}

func (c *ConfigProgramItem) ExpectedType() Type {
	return TypeBytes
}

type ConfigItemIface interface {
	New(name string) ConfigItemIface
	Parse(r io.Reader, process ProcessScan)
	String() string
	ExpectedType() Type
}

type ConfigAttrbute struct {
	Index int
	Name  string
	Item  ConfigItemIface
}

var configTypes = map[int]ConfigAttrbute{
	1:  {1, "BeaconType", new(ConfigShortItem)},
	2:  {2, "Port", new(ConfigShortItem)},
	3:  {3, "Sleep", new(ConfigIntegerItem)},
	4:  {4, "MaxGetSize", new(ConfigIntegerItem)},
	5:  {5, "Jitter", new(ConfigShortItem)},
	6:  {6, "MaxDNS", new(ConfigShortItem)},
	8:  {8, "C2Server", new(ConfigStringItem)},
	9:  {9, "UserAgent", new(ConfigStringItem)},
	10: {10, "HTTP_Post_URI", new(ConfigStringItem)},
	11: {11, "HTTPGetServerOutput", new(ConfigProgramItem)},
	12: {12, "HTTP_Get_Program", new(ConfigProgramItem)},
	13: {13, "HTTP_Post_Program", new(ConfigProgramItem)},
	14: {14, "Inject_Process", new(ConfigStringItem)},
	15: {15, "PipeName", new(ConfigStringItem)},
	19: {19, "DNS_idle", new(ConfigIntegerItem)},
	20: {20, "DNS_sleep", new(ConfigIntegerItem)},
	26: {26, "HTTP_Method1", new(ConfigStringItem)},
	27: {27, "HTTP_Method2", new(ConfigStringItem)},
	28: {28, "HttpPostChunk", new(ConfigIntegerItem)},
	29: {29, "Spawnto_x86", new(ConfigStringItem)},
	30: {30, "Spawnto_x64", new(ConfigStringItem)},
	32: {32, "Proxy_Host", new(ConfigStringItem)},
	33: {33, "Proxy_Username", new(ConfigStringItem)},
	34: {34, "Proxy_Password", new(ConfigStringItem)},
	37: {37, "Watermark", new(ConfigIntegerItem)},
	38: {38, "StageCleanup", new(ConfigShortItem)},
	39: {39, "CfgCaution", new(ConfigShortItem)},
	40: {40, "KillDate", new(ConfigIntegerItem)},
	54: {54, "Host_Header", new(ConfigStringItem)},
}

type Type int64

const (
	TypeUnconfigured Type = iota
	TypeShort
	TypeInteger
	TypeBytes
	TypeString
)

type ConfigExtractor struct {
	address         uintptr
	configEntrySize int
	Items           map[string]ConfigItemIface
}

func NewConfigExtractor(configAddress uintptr, buffer []byte, process ProcessScan) (*ConfigExtractor, error) {
	extractor := new(ConfigExtractor)
	configReader := bytes.NewBuffer(buffer)
	extractor.address = configAddress
	extractor.Items = make(map[string]ConfigItemIface)
	if process.Is64Bit {
		extractor.configEntrySize = 16
	} else {
		extractor.configEntrySize = 8
	}
	tmp := make([]byte, extractor.configEntrySize)
	configReader.Read(tmp)
	index := 1

	for configReader.Len() > 0 {
		var type_ Type
		if extractor.configEntrySize == 16 {
			type_ = Type(ReadInt64(configReader))
		} else {
			type_ = Type(ReadInt32(configReader))
		}
		if _, ok := configTypes[index]; !ok || type_ == TypeUnconfigured {
			tmp = make([]byte, extractor.configEntrySize/2)
			configReader.Read(tmp)
			index++
			continue
		}
		configType := configTypes[index]
		configItem := configType.Item.New(configType.Name)
		if configItem.ExpectedType() != type_ {
			return extractor, fmt.Errorf("serialized config format does not match configuration type")
		}
		configItem.Parse(configReader, process)

		rPos := len(buffer) - configReader.Len()
		if rPos%extractor.configEntrySize != 0 {
			tmp = make([]byte, extractor.configEntrySize-rPos%extractor.configEntrySize)
			configReader.Read(tmp)
		}
		extractor.Items[configType.Name] = configItem
		index++
	}
	return extractor, nil
}

func (parser *ConfigExtractor) GetConfigText() string {
	var s string
	for _, item := range parser.Items {
		s += "\t" + item.String() + "\n"
	}
	return s
}
