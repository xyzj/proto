// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: protocol_wlst.proto

package wlst_pb2

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// 数据单元标识
type UnitIdentification struct {
	// 信息点DA
	Pn int32 `protobuf:"varint,1,opt,name=pn,proto3" json:"pn,omitempty"`
	// 信息类DT
	Fn int32 `protobuf:"varint,2,opt,name=fn,proto3" json:"fn,omitempty"`
}

func (m *UnitIdentification) Reset()         { *m = UnitIdentification{} }
func (m *UnitIdentification) String() string { return proto.CompactTextString(m) }
func (*UnitIdentification) ProtoMessage()    {}
func (*UnitIdentification) Descriptor() ([]byte, []int) {
	return fileDescriptor_f614763c9ca1b9b8, []int{0}
}
func (m *UnitIdentification) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *UnitIdentification) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_UnitIdentification.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *UnitIdentification) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnitIdentification.Merge(m, src)
}
func (m *UnitIdentification) XXX_Size() int {
	return m.Size()
}
func (m *UnitIdentification) XXX_DiscardUnknown() {
	xxx_messageInfo_UnitIdentification.DiscardUnknown(m)
}

var xxx_messageInfo_UnitIdentification proto.InternalMessageInfo

func (m *UnitIdentification) GetPn() int32 {
	if m != nil {
		return m.Pn
	}
	return 0
}

func (m *UnitIdentification) GetFn() int32 {
	if m != nil {
		return m.Fn
	}
	return 0
}

// 头信息
type DataIdentification struct {
	// 数据单元标识，具体定义见详细结构
	UintID []*UnitIdentification `protobuf:"bytes,1,rep,name=uintID,proto3" json:"uintID,omitempty"`
	// 请求访问0-无数据，1-有数据
	Acd int32 `protobuf:"varint,2,opt,name=acd,proto3" json:"acd,omitempty"`
	// 时间戳，unix格式
	Tp int64 `protobuf:"varint,3,opt,name=tp,proto3" json:"tp,omitempty"`
	// 允许延迟的分钟数
	Delay int32 `protobuf:"varint,4,opt,name=delay,proto3" json:"delay,omitempty"`
	// 认证码
	Pw string `protobuf:"bytes,5,opt,name=pw,proto3" json:"pw,omitempty"`
	// 高优先级事件数量
	Ec1 int32 `protobuf:"varint,6,opt,name=ec1,proto3" json:"ec1,omitempty"`
	// 普通优先级事件数量
	Ec2 int32 `protobuf:"varint,7,opt,name=ec2,proto3" json:"ec2,omitempty"`
	// 顺序码0-15
	Seq int32 `protobuf:"varint,8,opt,name=seq,proto3" json:"seq,omitempty"`
	// afn 功能码
	Afn int32 `protobuf:"varint,9,opt,name=afn,proto3" json:"afn,omitempty"`
}

func (m *DataIdentification) Reset()         { *m = DataIdentification{} }
func (m *DataIdentification) String() string { return proto.CompactTextString(m) }
func (*DataIdentification) ProtoMessage()    {}
func (*DataIdentification) Descriptor() ([]byte, []int) {
	return fileDescriptor_f614763c9ca1b9b8, []int{1}
}
func (m *DataIdentification) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DataIdentification) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DataIdentification.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DataIdentification) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DataIdentification.Merge(m, src)
}
func (m *DataIdentification) XXX_Size() int {
	return m.Size()
}
func (m *DataIdentification) XXX_DiscardUnknown() {
	xxx_messageInfo_DataIdentification.DiscardUnknown(m)
}

var xxx_messageInfo_DataIdentification proto.InternalMessageInfo

func (m *DataIdentification) GetUintID() []*UnitIdentification {
	if m != nil {
		return m.UintID
	}
	return nil
}

func (m *DataIdentification) GetAcd() int32 {
	if m != nil {
		return m.Acd
	}
	return 0
}

func (m *DataIdentification) GetTp() int64 {
	if m != nil {
		return m.Tp
	}
	return 0
}

func (m *DataIdentification) GetDelay() int32 {
	if m != nil {
		return m.Delay
	}
	return 0
}

func (m *DataIdentification) GetPw() string {
	if m != nil {
		return m.Pw
	}
	return ""
}

func (m *DataIdentification) GetEc1() int32 {
	if m != nil {
		return m.Ec1
	}
	return 0
}

func (m *DataIdentification) GetEc2() int32 {
	if m != nil {
		return m.Ec2
	}
	return 0
}

func (m *DataIdentification) GetSeq() int32 {
	if m != nil {
		return m.Seq
	}
	return 0
}

func (m *DataIdentification) GetAfn() int32 {
	if m != nil {
		return m.Afn
	}
	return 0
}

// 状态应答
type WlstOpen_0000 struct {
	// pn: 0
	// fn: 1-全部确认，2-全部否认,3-部分确认/否认（要填充数据段，保留）
	DataID *DataIdentification `protobuf:"bytes,1,opt,name=DataID,json=dataID,proto3" json:"DataID,omitempty"`
	// 依据上行填
	Afn int32 `protobuf:"varint,3,opt,name=afn,proto3" json:"afn,omitempty"`
}

func (m *WlstOpen_0000) Reset()         { *m = WlstOpen_0000{} }
func (m *WlstOpen_0000) String() string { return proto.CompactTextString(m) }
func (*WlstOpen_0000) ProtoMessage()    {}
func (*WlstOpen_0000) Descriptor() ([]byte, []int) {
	return fileDescriptor_f614763c9ca1b9b8, []int{2}
}
func (m *WlstOpen_0000) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *WlstOpen_0000) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_WlstOpen_0000.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *WlstOpen_0000) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WlstOpen_0000.Merge(m, src)
}
func (m *WlstOpen_0000) XXX_Size() int {
	return m.Size()
}
func (m *WlstOpen_0000) XXX_DiscardUnknown() {
	xxx_messageInfo_WlstOpen_0000.DiscardUnknown(m)
}

var xxx_messageInfo_WlstOpen_0000 proto.InternalMessageInfo

func (m *WlstOpen_0000) GetDataID() *DataIdentification {
	if m != nil {
		return m.DataID
	}
	return nil
}

func (m *WlstOpen_0000) GetAfn() int32 {
	if m != nil {
		return m.Afn
	}
	return 0
}

// 复位下行
type WlstOpen_0101 struct {
	// pn: 0
	// fn: 1-硬件初始化（重启），2-数据区初始化，3-恢复出厂值，4-参数全体数据区
	DataID *DataIdentification `protobuf:"bytes,1,opt,name=DataID,json=dataID,proto3" json:"DataID,omitempty"`
}

func (m *WlstOpen_0101) Reset()         { *m = WlstOpen_0101{} }
func (m *WlstOpen_0101) String() string { return proto.CompactTextString(m) }
func (*WlstOpen_0101) ProtoMessage()    {}
func (*WlstOpen_0101) Descriptor() ([]byte, []int) {
	return fileDescriptor_f614763c9ca1b9b8, []int{3}
}
func (m *WlstOpen_0101) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *WlstOpen_0101) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_WlstOpen_0101.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *WlstOpen_0101) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WlstOpen_0101.Merge(m, src)
}
func (m *WlstOpen_0101) XXX_Size() int {
	return m.Size()
}
func (m *WlstOpen_0101) XXX_DiscardUnknown() {
	xxx_messageInfo_WlstOpen_0101.DiscardUnknown(m)
}

var xxx_messageInfo_WlstOpen_0101 proto.InternalMessageInfo

func (m *WlstOpen_0101) GetDataID() *DataIdentification {
	if m != nil {
		return m.DataID
	}
	return nil
}

// 登录上行
type WlstOpen_0902 struct {
	// pn: 0
	// fn: 1-登录，2-退出，3-心跳
	DataID *DataIdentification `protobuf:"bytes,1,opt,name=DataID,json=dataID,proto3" json:"DataID,omitempty"`
}

func (m *WlstOpen_0902) Reset()         { *m = WlstOpen_0902{} }
func (m *WlstOpen_0902) String() string { return proto.CompactTextString(m) }
func (*WlstOpen_0902) ProtoMessage()    {}
func (*WlstOpen_0902) Descriptor() ([]byte, []int) {
	return fileDescriptor_f614763c9ca1b9b8, []int{4}
}
func (m *WlstOpen_0902) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *WlstOpen_0902) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_WlstOpen_0902.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *WlstOpen_0902) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WlstOpen_0902.Merge(m, src)
}
func (m *WlstOpen_0902) XXX_Size() int {
	return m.Size()
}
func (m *WlstOpen_0902) XXX_DiscardUnknown() {
	xxx_messageInfo_WlstOpen_0902.DiscardUnknown(m)
}

var xxx_messageInfo_WlstOpen_0902 proto.InternalMessageInfo

func (m *WlstOpen_0902) GetDataID() *DataIdentification {
	if m != nil {
		return m.DataID
	}
	return nil
}

func init() {
	proto.RegisterType((*UnitIdentification)(nil), "wlst.pb2.UnitIdentification")
	proto.RegisterType((*DataIdentification)(nil), "wlst.pb2.DataIdentification")
	proto.RegisterType((*WlstOpen_0000)(nil), "wlst.pb2.Wlst_open_0000")
	proto.RegisterType((*WlstOpen_0101)(nil), "wlst.pb2.Wlst_open_0101")
	proto.RegisterType((*WlstOpen_0902)(nil), "wlst.pb2.Wlst_open_0902")
}

func init() { proto.RegisterFile("protocol_wlst.proto", fileDescriptor_f614763c9ca1b9b8) }

var fileDescriptor_f614763c9ca1b9b8 = []byte{
	// 312 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0x41, 0x4b, 0x84, 0x40,
	0x1c, 0xc5, 0x77, 0x34, 0x6d, 0x77, 0x82, 0x25, 0xa6, 0x0e, 0x43, 0xc4, 0x20, 0x9e, 0x3c, 0xc9,
	0x68, 0x7b, 0xe9, 0x1a, 0x12, 0xed, 0x55, 0x88, 0xba, 0x89, 0xab, 0x23, 0x08, 0x32, 0xce, 0xe6,
	0x84, 0xf4, 0x2d, 0xfa, 0x58, 0x1d, 0xf7, 0x18, 0x9d, 0x42, 0xbf, 0x48, 0x38, 0xa3, 0xc4, 0xee,
	0xde, 0xf6, 0xf6, 0x7f, 0x8f, 0xbf, 0xbf, 0xe7, 0xfb, 0x33, 0xf0, 0x4a, 0xbc, 0xd5, 0xb2, 0xce,
	0xea, 0x2a, 0x69, 0xab, 0x46, 0xfa, 0x4a, 0xa1, 0xb9, 0x9e, 0x37, 0xa1, 0xbb, 0x82, 0xe8, 0x99,
	0x97, 0x72, 0x9d, 0x33, 0x2e, 0xcb, 0xa2, 0xcc, 0x52, 0x59, 0xd6, 0x1c, 0x2d, 0xa1, 0x21, 0x38,
	0x06, 0x0e, 0xf0, 0xac, 0xd8, 0x10, 0x4a, 0x17, 0x1c, 0x1b, 0x5a, 0x17, 0xdc, 0xfd, 0x01, 0x10,
	0x45, 0xa9, 0x4c, 0x0f, 0x3e, 0x5b, 0x41, 0xfb, 0xbd, 0xe4, 0x72, 0x1d, 0x61, 0xe0, 0x98, 0xde,
	0x45, 0x78, 0xeb, 0x4f, 0x39, 0xfe, 0x71, 0x48, 0x3c, 0xee, 0xa2, 0x4b, 0x68, 0xa6, 0x59, 0x3e,
	0xd2, 0x87, 0x71, 0x88, 0x93, 0x02, 0x9b, 0x0e, 0xf0, 0xcc, 0xd8, 0x90, 0x02, 0x5d, 0x43, 0x2b,
	0x67, 0x55, 0xfa, 0x81, 0xcf, 0xd4, 0x8e, 0x16, 0xea, 0x27, 0x5b, 0x6c, 0x39, 0xc0, 0x5b, 0xc4,
	0x86, 0x68, 0x07, 0x0e, 0xcb, 0x02, 0x6c, 0x6b, 0x0e, 0xcb, 0x02, 0xed, 0x84, 0xf8, 0x7c, 0x72,
	0xc2, 0xc1, 0x69, 0xd8, 0x16, 0xcf, 0xb5, 0xd3, 0xb0, 0xad, 0x4a, 0x2f, 0x38, 0x5e, 0x8c, 0xe9,
	0x05, 0x77, 0x5f, 0xe1, 0xf2, 0xa5, 0x6a, 0x64, 0x52, 0x0b, 0xc6, 0x13, 0x4a, 0x29, 0x1d, 0x7a,
	0xa9, 0xb6, 0x91, 0x3a, 0xc9, 0x5e, 0xaf, 0xe3, 0x2b, 0xc4, 0x76, 0xae, 0x76, 0x27, 0xb2, 0xf9,
	0x4f, 0x7e, 0xdc, 0x23, 0x07, 0x34, 0x38, 0x8d, 0x7c, 0xc0, 0xb9, 0xa7, 0xe1, 0x69, 0x9c, 0x87,
	0x9b, 0xaf, 0x8e, 0x80, 0x5d, 0x47, 0xc0, 0x6f, 0x47, 0xc0, 0x67, 0x4f, 0x66, 0xbb, 0x9e, 0xcc,
	0xbe, 0x7b, 0x32, 0x7b, 0x02, 0x1b, 0x5b, 0xbd, 0x94, 0xbb, 0xbf, 0x00, 0x00, 0x00, 0xff, 0xff,
	0x02, 0xea, 0x99, 0xec, 0x40, 0x02, 0x00, 0x00,
}

func (m *UnitIdentification) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *UnitIdentification) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *UnitIdentification) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Fn != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Fn))
		i--
		dAtA[i] = 0x10
	}
	if m.Pn != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Pn))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *DataIdentification) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DataIdentification) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *DataIdentification) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Afn != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Afn))
		i--
		dAtA[i] = 0x48
	}
	if m.Seq != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Seq))
		i--
		dAtA[i] = 0x40
	}
	if m.Ec2 != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Ec2))
		i--
		dAtA[i] = 0x38
	}
	if m.Ec1 != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Ec1))
		i--
		dAtA[i] = 0x30
	}
	if len(m.Pw) > 0 {
		i -= len(m.Pw)
		copy(dAtA[i:], m.Pw)
		i = encodeVarintProtocolWlst(dAtA, i, uint64(len(m.Pw)))
		i--
		dAtA[i] = 0x2a
	}
	if m.Delay != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Delay))
		i--
		dAtA[i] = 0x20
	}
	if m.Tp != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Tp))
		i--
		dAtA[i] = 0x18
	}
	if m.Acd != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Acd))
		i--
		dAtA[i] = 0x10
	}
	if len(m.UintID) > 0 {
		for iNdEx := len(m.UintID) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.UintID[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintProtocolWlst(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *WlstOpen_0000) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *WlstOpen_0000) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *WlstOpen_0000) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Afn != 0 {
		i = encodeVarintProtocolWlst(dAtA, i, uint64(m.Afn))
		i--
		dAtA[i] = 0x18
	}
	if m.DataID != nil {
		{
			size, err := m.DataID.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintProtocolWlst(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *WlstOpen_0101) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *WlstOpen_0101) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *WlstOpen_0101) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.DataID != nil {
		{
			size, err := m.DataID.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintProtocolWlst(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *WlstOpen_0902) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *WlstOpen_0902) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *WlstOpen_0902) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.DataID != nil {
		{
			size, err := m.DataID.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintProtocolWlst(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintProtocolWlst(dAtA []byte, offset int, v uint64) int {
	offset -= sovProtocolWlst(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *UnitIdentification) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Pn != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Pn))
	}
	if m.Fn != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Fn))
	}
	return n
}

func (m *DataIdentification) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.UintID) > 0 {
		for _, e := range m.UintID {
			l = e.Size()
			n += 1 + l + sovProtocolWlst(uint64(l))
		}
	}
	if m.Acd != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Acd))
	}
	if m.Tp != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Tp))
	}
	if m.Delay != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Delay))
	}
	l = len(m.Pw)
	if l > 0 {
		n += 1 + l + sovProtocolWlst(uint64(l))
	}
	if m.Ec1 != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Ec1))
	}
	if m.Ec2 != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Ec2))
	}
	if m.Seq != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Seq))
	}
	if m.Afn != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Afn))
	}
	return n
}

func (m *WlstOpen_0000) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.DataID != nil {
		l = m.DataID.Size()
		n += 1 + l + sovProtocolWlst(uint64(l))
	}
	if m.Afn != 0 {
		n += 1 + sovProtocolWlst(uint64(m.Afn))
	}
	return n
}

func (m *WlstOpen_0101) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.DataID != nil {
		l = m.DataID.Size()
		n += 1 + l + sovProtocolWlst(uint64(l))
	}
	return n
}

func (m *WlstOpen_0902) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.DataID != nil {
		l = m.DataID.Size()
		n += 1 + l + sovProtocolWlst(uint64(l))
	}
	return n
}

func sovProtocolWlst(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozProtocolWlst(x uint64) (n int) {
	return sovProtocolWlst(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *UnitIdentification) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocolWlst
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: UnitIdentification: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: UnitIdentification: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Pn", wireType)
			}
			m.Pn = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Pn |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Fn", wireType)
			}
			m.Fn = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Fn |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipProtocolWlst(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *DataIdentification) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocolWlst
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: DataIdentification: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DataIdentification: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UintID", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.UintID = append(m.UintID, &UnitIdentification{})
			if err := m.UintID[len(m.UintID)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Acd", wireType)
			}
			m.Acd = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Acd |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Tp", wireType)
			}
			m.Tp = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Tp |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Delay", wireType)
			}
			m.Delay = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Delay |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Pw", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Pw = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ec1", wireType)
			}
			m.Ec1 = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Ec1 |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ec2", wireType)
			}
			m.Ec2 = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Ec2 |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 8:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Seq", wireType)
			}
			m.Seq = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Seq |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 9:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Afn", wireType)
			}
			m.Afn = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Afn |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipProtocolWlst(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *WlstOpen_0000) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocolWlst
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Wlst_open_0000: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Wlst_open_0000: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DataID", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.DataID == nil {
				m.DataID = &DataIdentification{}
			}
			if err := m.DataID.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Afn", wireType)
			}
			m.Afn = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Afn |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipProtocolWlst(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *WlstOpen_0101) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocolWlst
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Wlst_open_0101: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Wlst_open_0101: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DataID", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.DataID == nil {
				m.DataID = &DataIdentification{}
			}
			if err := m.DataID.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProtocolWlst(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *WlstOpen_0902) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowProtocolWlst
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Wlst_open_0902: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Wlst_open_0902: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DataID", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.DataID == nil {
				m.DataID = &DataIdentification{}
			}
			if err := m.DataID.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipProtocolWlst(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthProtocolWlst
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipProtocolWlst(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowProtocolWlst
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowProtocolWlst
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthProtocolWlst
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupProtocolWlst
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthProtocolWlst
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthProtocolWlst        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowProtocolWlst          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupProtocolWlst = fmt.Errorf("proto: unexpected end of group")
)
