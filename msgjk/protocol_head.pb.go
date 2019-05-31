// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protocol_head.proto

package wlst_pb2

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Head struct {
	//mod：1-系统指令，2-数传指令，3-SQL指令，4-错误数据
	Mod int32 `protobuf:"varint,1,opt,name=mod,proto3" json:"mod,omitempty"`
	//src：1-通讯服务，2-数据服务，3-客户端，4-串口采集（光照度，GPS），5-控制台，6-远程升级, 7-webservice接口
	Src int32 `protobuf:"varint,2,opt,name=src,proto3" json:"src,omitempty"`
	//ver：1-内部协议版本v1.0
	Ver int32 `protobuf:"varint,3,opt,name=ver,proto3" json:"ver,omitempty"`
	//tver：1-公司终端协议版本,2-合肥版本协议
	Tver int32 `protobuf:"varint,4,opt,name=tver,proto3" json:"tver,omitempty"`
	//tra：1-数据通过模块直接传输，2-数据通过485传输
	Tra int32 `protobuf:"varint,5,opt,name=tra,proto3" json:"tra,omitempty"`
	//ret: 发送等级，0-normal，1-high
	Ret int32 `protobuf:"varint,6,opt,name=ret,proto3" json:"ret,omitempty"`
	//cmd：单位.设备.指令
	Cmd  string  `protobuf:"bytes,7,opt,name=cmd,proto3" json:"cmd,omitempty"`
	Code float64 `protobuf:"fixed64,8,opt,name=code,proto3" json:"code,omitempty"`
	//目的地:1-终端，2-数据服务
	Dst int32 `protobuf:"varint,9,opt,name=dst,proto3" json:"dst,omitempty"`
	//多路通信的绑定基础地址
	BaseAddr int32 `protobuf:"varint,10,opt,name=base_addr,json=baseAddr,proto3" json:"base_addr,omitempty"`
	Gid      int32 `protobuf:"varint,11,opt,name=gid,proto3" json:"gid,omitempty"`
	Rcv      int32 `protobuf:"varint,12,opt,name=rcv,proto3" json:"rcv,omitempty"`
	// 命令序号，long型递增循环
	Idx int64 `protobuf:"varint,13,opt,name=idx,proto3" json:"idx,omitempty"`
	// 当前消息发出时间戳
	Dt                   int64    `protobuf:"varint,15,opt,name=dt,proto3" json:"dt,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Head) Reset()         { *m = Head{} }
func (m *Head) String() string { return proto.CompactTextString(m) }
func (*Head) ProtoMessage()    {}
func (*Head) Descriptor() ([]byte, []int) {
	return fileDescriptor_0cecebaa1d05d52d, []int{0}
}

func (m *Head) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Head.Unmarshal(m, b)
}
func (m *Head) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Head.Marshal(b, m, deterministic)
}
func (m *Head) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Head.Merge(m, src)
}
func (m *Head) XXX_Size() int {
	return xxx_messageInfo_Head.Size(m)
}
func (m *Head) XXX_DiscardUnknown() {
	xxx_messageInfo_Head.DiscardUnknown(m)
}

var xxx_messageInfo_Head proto.InternalMessageInfo

func (m *Head) GetMod() int32 {
	if m != nil {
		return m.Mod
	}
	return 0
}

func (m *Head) GetSrc() int32 {
	if m != nil {
		return m.Src
	}
	return 0
}

func (m *Head) GetVer() int32 {
	if m != nil {
		return m.Ver
	}
	return 0
}

func (m *Head) GetTver() int32 {
	if m != nil {
		return m.Tver
	}
	return 0
}

func (m *Head) GetTra() int32 {
	if m != nil {
		return m.Tra
	}
	return 0
}

func (m *Head) GetRet() int32 {
	if m != nil {
		return m.Ret
	}
	return 0
}

func (m *Head) GetCmd() string {
	if m != nil {
		return m.Cmd
	}
	return ""
}

func (m *Head) GetCode() float64 {
	if m != nil {
		return m.Code
	}
	return 0
}

func (m *Head) GetDst() int32 {
	if m != nil {
		return m.Dst
	}
	return 0
}

func (m *Head) GetBaseAddr() int32 {
	if m != nil {
		return m.BaseAddr
	}
	return 0
}

func (m *Head) GetGid() int32 {
	if m != nil {
		return m.Gid
	}
	return 0
}

func (m *Head) GetRcv() int32 {
	if m != nil {
		return m.Rcv
	}
	return 0
}

func (m *Head) GetIdx() int64 {
	if m != nil {
		return m.Idx
	}
	return 0
}

func (m *Head) GetDt() int64 {
	if m != nil {
		return m.Dt
	}
	return 0
}

type Args struct {
	//ip：目的ip
	Ip []int64 `protobuf:"varint,1,rep,packed,name=ip,proto3" json:"ip,omitempty"`
	//port：目的端口
	Port int32 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	//addr：终端地址，列表格式
	Addr []int64 `protobuf:"varint,3,rep,packed,name=addr,proto3" json:"addr,omitempty"`
	//sim：手机卡号，字符串格式
	Sim string `protobuf:"bytes,4,opt,name=sim,proto3" json:"sim,omitempty"`
	//cid：集中器地址
	Cid int32 `protobuf:"varint,5,opt,name=cid,proto3" json:"cid,omitempty"`
	// 手机卡号，和ip对应
	Sims []int64 `protobuf:"varint,6,rep,packed,name=sims,proto3" json:"sims,omitempty"`
	//字符串压缩格式地址（xx-xx）
	Saddr  []string `protobuf:"bytes,7,rep,name=saddr,proto3" json:"saddr,omitempty"`
	Status []int64  `protobuf:"varint,8,rep,packed,name=status,proto3" json:"status,omitempty"`
	// 485校验, 0-无校验，1-偶校验,防盗默认1,其他默认0
	Rc int32 `protobuf:"varint,9,opt,name=rc,proto3" json:"rc,omitempty"`
	// 485波特率，0-300,1-600,2-1200,3-2400,4-4800,5-9600，防盗默认2,其他默认5
	Br int32 `protobuf:"varint,10,opt,name=br,proto3" json:"br,omitempty"`
	// 设备标识，用于电信nb平台，本公司产品使用0xd0
	DataFlag             []int32  `protobuf:"varint,11,rep,packed,name=data_flag,json=dataFlag,proto3" json:"data_flag,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Args) Reset()         { *m = Args{} }
func (m *Args) String() string { return proto.CompactTextString(m) }
func (*Args) ProtoMessage()    {}
func (*Args) Descriptor() ([]byte, []int) {
	return fileDescriptor_0cecebaa1d05d52d, []int{1}
}

func (m *Args) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Args.Unmarshal(m, b)
}
func (m *Args) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Args.Marshal(b, m, deterministic)
}
func (m *Args) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Args.Merge(m, src)
}
func (m *Args) XXX_Size() int {
	return xxx_messageInfo_Args.Size(m)
}
func (m *Args) XXX_DiscardUnknown() {
	xxx_messageInfo_Args.DiscardUnknown(m)
}

var xxx_messageInfo_Args proto.InternalMessageInfo

func (m *Args) GetIp() []int64 {
	if m != nil {
		return m.Ip
	}
	return nil
}

func (m *Args) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Args) GetAddr() []int64 {
	if m != nil {
		return m.Addr
	}
	return nil
}

func (m *Args) GetSim() string {
	if m != nil {
		return m.Sim
	}
	return ""
}

func (m *Args) GetCid() int32 {
	if m != nil {
		return m.Cid
	}
	return 0
}

func (m *Args) GetSims() []int64 {
	if m != nil {
		return m.Sims
	}
	return nil
}

func (m *Args) GetSaddr() []string {
	if m != nil {
		return m.Saddr
	}
	return nil
}

func (m *Args) GetStatus() []int64 {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *Args) GetRc() int32 {
	if m != nil {
		return m.Rc
	}
	return 0
}

func (m *Args) GetBr() int32 {
	if m != nil {
		return m.Br
	}
	return 0
}

func (m *Args) GetDataFlag() []int32 {
	if m != nil {
		return m.DataFlag
	}
	return nil
}

type SysCommands struct {
	Port int32 `protobuf:"varint,1,opt,name=port,proto3" json:"port,omitempty"`
	//在线
	OnlineRtus []int64 `protobuf:"varint,2,rep,packed,name=online_rtus,json=onlineRtus,proto3" json:"online_rtus,omitempty"`
	OnlineId   []int32 `protobuf:"varint,3,rep,packed,name=online_id,json=onlineId,proto3" json:"online_id,omitempty"`
	OnlineIp   []int64 `protobuf:"varint,4,rep,packed,name=online_ip,json=onlineIp,proto3" json:"online_ip,omitempty"`
	//日志信息
	LoggerMsg            string                    `protobuf:"bytes,5,opt,name=logger_msg,json=loggerMsg,proto3" json:"logger_msg,omitempty"`
	OnlineInfo           []*SysCommands_OnlineInfo `protobuf:"bytes,6,rep,name=online_info,json=onlineInfo,proto3" json:"online_info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *SysCommands) Reset()         { *m = SysCommands{} }
func (m *SysCommands) String() string { return proto.CompactTextString(m) }
func (*SysCommands) ProtoMessage()    {}
func (*SysCommands) Descriptor() ([]byte, []int) {
	return fileDescriptor_0cecebaa1d05d52d, []int{2}
}

func (m *SysCommands) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SysCommands.Unmarshal(m, b)
}
func (m *SysCommands) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SysCommands.Marshal(b, m, deterministic)
}
func (m *SysCommands) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SysCommands.Merge(m, src)
}
func (m *SysCommands) XXX_Size() int {
	return xxx_messageInfo_SysCommands.Size(m)
}
func (m *SysCommands) XXX_DiscardUnknown() {
	xxx_messageInfo_SysCommands.DiscardUnknown(m)
}

var xxx_messageInfo_SysCommands proto.InternalMessageInfo

func (m *SysCommands) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *SysCommands) GetOnlineRtus() []int64 {
	if m != nil {
		return m.OnlineRtus
	}
	return nil
}

func (m *SysCommands) GetOnlineId() []int32 {
	if m != nil {
		return m.OnlineId
	}
	return nil
}

func (m *SysCommands) GetOnlineIp() []int64 {
	if m != nil {
		return m.OnlineIp
	}
	return nil
}

func (m *SysCommands) GetLoggerMsg() string {
	if m != nil {
		return m.LoggerMsg
	}
	return ""
}

func (m *SysCommands) GetOnlineInfo() []*SysCommands_OnlineInfo {
	if m != nil {
		return m.OnlineInfo
	}
	return nil
}

type SysCommands_OnlineInfo struct {
	Ip                   int64    `protobuf:"varint,1,opt,name=ip,proto3" json:"ip,omitempty"`
	Members              []string `protobuf:"bytes,2,rep,name=members,proto3" json:"members,omitempty"`
	NetType              int32    `protobuf:"varint,3,opt,name=net_type,json=netType,proto3" json:"net_type,omitempty"`
	Signal               int32    `protobuf:"varint,4,opt,name=signal,proto3" json:"signal,omitempty"`
	PhyId                int64    `protobuf:"varint,5,opt,name=phy_id,json=phyId,proto3" json:"phy_id,omitempty"`
	Imei                 int64    `protobuf:"varint,6,opt,name=imei,proto3" json:"imei,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SysCommands_OnlineInfo) Reset()         { *m = SysCommands_OnlineInfo{} }
func (m *SysCommands_OnlineInfo) String() string { return proto.CompactTextString(m) }
func (*SysCommands_OnlineInfo) ProtoMessage()    {}
func (*SysCommands_OnlineInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_0cecebaa1d05d52d, []int{2, 0}
}

func (m *SysCommands_OnlineInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SysCommands_OnlineInfo.Unmarshal(m, b)
}
func (m *SysCommands_OnlineInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SysCommands_OnlineInfo.Marshal(b, m, deterministic)
}
func (m *SysCommands_OnlineInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SysCommands_OnlineInfo.Merge(m, src)
}
func (m *SysCommands_OnlineInfo) XXX_Size() int {
	return xxx_messageInfo_SysCommands_OnlineInfo.Size(m)
}
func (m *SysCommands_OnlineInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_SysCommands_OnlineInfo.DiscardUnknown(m)
}

var xxx_messageInfo_SysCommands_OnlineInfo proto.InternalMessageInfo

func (m *SysCommands_OnlineInfo) GetIp() int64 {
	if m != nil {
		return m.Ip
	}
	return 0
}

func (m *SysCommands_OnlineInfo) GetMembers() []string {
	if m != nil {
		return m.Members
	}
	return nil
}

func (m *SysCommands_OnlineInfo) GetNetType() int32 {
	if m != nil {
		return m.NetType
	}
	return 0
}

func (m *SysCommands_OnlineInfo) GetSignal() int32 {
	if m != nil {
		return m.Signal
	}
	return 0
}

func (m *SysCommands_OnlineInfo) GetPhyId() int64 {
	if m != nil {
		return m.PhyId
	}
	return 0
}

func (m *SysCommands_OnlineInfo) GetImei() int64 {
	if m != nil {
		return m.Imei
	}
	return 0
}

type Passthrough struct {
	// 序号
	CmdIdx int32 `protobuf:"varint,1,opt,name=cmd_idx,json=cmdIdx,proto3" json:"cmd_idx,omitempty"`
	// 标识
	DataMark int32 `protobuf:"varint,2,opt,name=data_mark,json=dataMark,proto3" json:"data_mark,omitempty"`
	// 数据
	PkgData []int32 `protobuf:"varint,3,rep,packed,name=pkg_data,json=pkgData,proto3" json:"pkg_data,omitempty"`
	// 状态
	Status               int32    `protobuf:"varint,4,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Passthrough) Reset()         { *m = Passthrough{} }
func (m *Passthrough) String() string { return proto.CompactTextString(m) }
func (*Passthrough) ProtoMessage()    {}
func (*Passthrough) Descriptor() ([]byte, []int) {
	return fileDescriptor_0cecebaa1d05d52d, []int{3}
}

func (m *Passthrough) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Passthrough.Unmarshal(m, b)
}
func (m *Passthrough) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Passthrough.Marshal(b, m, deterministic)
}
func (m *Passthrough) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Passthrough.Merge(m, src)
}
func (m *Passthrough) XXX_Size() int {
	return xxx_messageInfo_Passthrough.Size(m)
}
func (m *Passthrough) XXX_DiscardUnknown() {
	xxx_messageInfo_Passthrough.DiscardUnknown(m)
}

var xxx_messageInfo_Passthrough proto.InternalMessageInfo

func (m *Passthrough) GetCmdIdx() int32 {
	if m != nil {
		return m.CmdIdx
	}
	return 0
}

func (m *Passthrough) GetDataMark() int32 {
	if m != nil {
		return m.DataMark
	}
	return 0
}

func (m *Passthrough) GetPkgData() []int32 {
	if m != nil {
		return m.PkgData
	}
	return nil
}

func (m *Passthrough) GetStatus() int32 {
	if m != nil {
		return m.Status
	}
	return 0
}

func init() {
	proto.RegisterType((*Head)(nil), "wlst.pb2.Head")
	proto.RegisterType((*Args)(nil), "wlst.pb2.Args")
	proto.RegisterType((*SysCommands)(nil), "wlst.pb2.SysCommands")
	proto.RegisterType((*SysCommands_OnlineInfo)(nil), "wlst.pb2.SysCommands.OnlineInfo")
	proto.RegisterType((*Passthrough)(nil), "wlst.pb2.Passthrough")
}

func init() { proto.RegisterFile("protocol_head.proto", fileDescriptor_0cecebaa1d05d52d) }

var fileDescriptor_0cecebaa1d05d52d = []byte{
	// 617 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x94, 0xcd, 0x72, 0xd3, 0x30,
	0x10, 0xc7, 0xc7, 0x76, 0xbe, 0xbc, 0xe1, 0xa3, 0x23, 0xa0, 0x88, 0x32, 0x9d, 0x7a, 0xc2, 0x25,
	0xa7, 0x1c, 0xca, 0x13, 0xb4, 0x30, 0x4c, 0x7b, 0xe8, 0xc0, 0x18, 0xee, 0x1e, 0xc5, 0x52, 0x1d,
	0x4d, 0xfc, 0xa1, 0x91, 0xd4, 0xd0, 0x70, 0xe3, 0x09, 0xb8, 0xf0, 0xaa, 0xdc, 0x99, 0x5d, 0xd9,
	0x69, 0x6e, 0xbb, 0xbf, 0xac, 0xe4, 0xff, 0xfe, 0x77, 0x15, 0x78, 0x65, 0x6c, 0xe7, 0xbb, 0xb2,
	0xab, 0x8b, 0x8d, 0x12, 0x72, 0x45, 0x19, 0x9b, 0xfd, 0xac, 0x9d, 0x5f, 0x99, 0xf5, 0xe5, 0xe2,
	0x4f, 0x0c, 0xa3, 0x1b, 0x25, 0x24, 0x3b, 0x81, 0xa4, 0xe9, 0x24, 0x8f, 0xb2, 0x68, 0x39, 0xce,
	0x31, 0x44, 0xe2, 0x6c, 0xc9, 0xe3, 0x40, 0x9c, 0x2d, 0x91, 0xec, 0x94, 0xe5, 0x49, 0x20, 0x3b,
	0x65, 0x19, 0x83, 0x91, 0x47, 0x34, 0x22, 0x44, 0x31, 0x56, 0x79, 0x2b, 0xf8, 0x38, 0x54, 0x79,
	0x2b, 0x90, 0x58, 0xe5, 0xf9, 0x24, 0x10, 0xab, 0x3c, 0x92, 0xb2, 0x91, 0x7c, 0x9a, 0x45, 0xcb,
	0x34, 0xc7, 0x10, 0x6f, 0x2a, 0x3b, 0xa9, 0xf8, 0x2c, 0x8b, 0x96, 0x51, 0x4e, 0x31, 0x56, 0x49,
	0xe7, 0x79, 0x1a, 0xce, 0x49, 0xe7, 0xd9, 0x7b, 0x48, 0xd7, 0xc2, 0xa9, 0x42, 0x48, 0x69, 0x39,
	0x10, 0x9f, 0x21, 0xb8, 0x92, 0x92, 0x3e, 0x5c, 0x69, 0xc9, 0xe7, 0xa1, 0xbc, 0xd2, 0xd4, 0x82,
	0x2d, 0x77, 0xfc, 0x59, 0xff, 0xe1, 0x72, 0x87, 0x44, 0xcb, 0x47, 0xfe, 0x3c, 0x8b, 0x96, 0x49,
	0x8e, 0x21, 0x7b, 0x01, 0xb1, 0xf4, 0xfc, 0x25, 0x81, 0x58, 0xfa, 0xc5, 0xbf, 0x08, 0x46, 0x57,
	0xb6, 0x72, 0x8c, 0x41, 0xac, 0x0d, 0x8f, 0xb2, 0x64, 0x99, 0x5c, 0xc7, 0x27, 0x51, 0x1e, 0x6b,
	0x83, 0x2a, 0x4d, 0x67, 0x7d, 0x6f, 0x0a, 0xc5, 0xec, 0x14, 0x46, 0x24, 0x27, 0x39, 0x54, 0x52,
	0x4e, 0xfe, 0xe9, 0x86, 0xac, 0x49, 0x73, 0x0c, 0xa9, 0x6b, 0x2d, 0x07, 0x67, 0x4a, 0x2d, 0xf1,
	0xac, 0xd3, 0x8d, 0xe3, 0x93, 0xa7, 0xb3, 0x98, 0xb3, 0xd7, 0x30, 0x76, 0x74, 0xe9, 0x34, 0x4b,
	0x96, 0x69, 0x1e, 0x12, 0x76, 0x06, 0x13, 0xe7, 0x85, 0x7f, 0x70, 0x7c, 0x76, 0xa8, 0xef, 0x09,
	0xb6, 0x61, 0xcb, 0xde, 0xaa, 0xd8, 0x96, 0x98, 0xaf, 0x07, 0x8b, 0xe2, 0xb5, 0x65, 0x17, 0x90,
	0x4a, 0xe1, 0x45, 0x71, 0x5f, 0x8b, 0x8a, 0xcf, 0xb3, 0x64, 0x39, 0xa6, 0xe3, 0x33, 0x84, 0x5f,
	0x6a, 0x51, 0x2d, 0x7e, 0x27, 0x30, 0xff, 0xbe, 0x77, 0x9f, 0xba, 0xa6, 0x11, 0xad, 0x74, 0x87,
	0x56, 0xa3, 0xa3, 0x56, 0x3f, 0xc0, 0xbc, 0x6b, 0x6b, 0xdd, 0xaa, 0xc2, 0xa2, 0x8a, 0xf8, 0xa0,
	0x02, 0x02, 0xce, 0x51, 0xc9, 0x05, 0xa4, 0x7d, 0x91, 0x96, 0x64, 0x4a, 0xff, 0xa5, 0x00, 0x6f,
	0xe5, 0x71, 0x81, 0xe1, 0xa3, 0xc3, 0x1d, 0x43, 0x81, 0x61, 0xe7, 0x00, 0x75, 0x57, 0x55, 0xca,
	0x16, 0x8d, 0xab, 0xc8, 0xae, 0x34, 0x4f, 0x03, 0xb9, 0x73, 0x15, 0xbb, 0x3a, 0xa8, 0xd0, 0xed,
	0x7d, 0x47, 0xde, 0xcd, 0x2f, 0xb3, 0xd5, 0xb0, 0xd3, 0xab, 0xa3, 0x2e, 0x56, 0x5f, 0xc3, 0x9d,
	0xed, 0x7d, 0x37, 0x68, 0xc4, 0xf8, 0xec, 0x6f, 0x04, 0xf0, 0xf4, 0x13, 0x9a, 0x45, 0xa3, 0xa6,
	0x1d, 0xd0, 0x86, 0x71, 0x98, 0x36, 0xaa, 0x59, 0x2b, 0x1b, 0x7a, 0x4c, 0xf3, 0x21, 0x65, 0xef,
	0x60, 0xd6, 0x2a, 0x5f, 0xf8, 0xbd, 0x51, 0xfd, 0x3b, 0x98, 0xb6, 0xca, 0xff, 0xd8, 0x1b, 0xc5,
	0x4e, 0x61, 0xe2, 0x74, 0xd5, 0x8a, 0xba, 0x7f, 0x0d, 0x7d, 0xc6, 0xde, 0xc0, 0xc4, 0x6c, 0xf6,
	0x45, 0x3f, 0xf8, 0x24, 0x1f, 0x9b, 0xcd, 0xfe, 0x96, 0x16, 0x5e, 0x37, 0x4a, 0xd3, 0xab, 0x48,
	0x72, 0x8a, 0x17, 0xbf, 0x60, 0xfe, 0x4d, 0x38, 0xe7, 0x37, 0xb6, 0x7b, 0xa8, 0x36, 0xec, 0x2d,
	0x4c, 0xcb, 0x46, 0x16, 0xb8, 0xb0, 0x61, 0x0a, 0x93, 0xb2, 0x91, 0xb7, 0xf2, 0x11, 0x9f, 0x01,
	0x0d, 0xb3, 0x11, 0x76, 0xdb, 0xef, 0x22, 0x0d, 0xf2, 0x4e, 0xd8, 0x2d, 0x3b, 0x87, 0x99, 0xd9,
	0x56, 0x05, 0xe6, 0x47, 0xf6, 0x4f, 0xcd, 0xb6, 0xfa, 0x2c, 0xbc, 0x20, 0x99, 0x61, 0x89, 0x06,
	0x99, 0x94, 0x5d, 0xc7, 0x37, 0xd1, 0x7a, 0x42, 0x7f, 0x0f, 0x1f, 0xff, 0x07, 0x00, 0x00, 0xff,
	0xff, 0x30, 0x08, 0x6f, 0xf8, 0x35, 0x04, 0x00, 0x00,
}
