# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protocol_head.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='protocol_head.proto',
  package='wlst.pb2',
  syntax='proto3',
  serialized_pb=_b('\n\x13protocol_head.proto\x12\x08wlst.pb2\"\xc3\x01\n\x04Head\x12\x0b\n\x03mod\x18\x01 \x01(\x05\x12\x0b\n\x03src\x18\x02 \x01(\x05\x12\x0b\n\x03ver\x18\x03 \x01(\x05\x12\x0c\n\x04tver\x18\x04 \x01(\x05\x12\x0b\n\x03tra\x18\x05 \x01(\x05\x12\x0b\n\x03ret\x18\x06 \x01(\x05\x12\x0b\n\x03\x63md\x18\x07 \x01(\t\x12\x0c\n\x04\x63ode\x18\x08 \x01(\x01\x12\x0b\n\x03\x64st\x18\t \x01(\x05\x12\x11\n\tbase_addr\x18\n \x01(\x05\x12\x0b\n\x03gid\x18\x0b \x01(\x05\x12\x0b\n\x03rcv\x18\x0c \x01(\x05\x12\x0b\n\x03idx\x18\r \x01(\x03\x12\n\n\x02\x64t\x18\x0f \x01(\x03\"\xb4\x01\n\x04\x41rgs\x12\x0e\n\x02ip\x18\x01 \x03(\x03\x42\x02\x10\x01\x12\x0c\n\x04port\x18\x02 \x01(\x05\x12\x10\n\x04\x61\x64\x64r\x18\x03 \x03(\x03\x42\x02\x10\x01\x12\x0b\n\x03sim\x18\x04 \x01(\t\x12\x0b\n\x03\x63id\x18\x05 \x01(\x05\x12\x10\n\x04sims\x18\x06 \x03(\x03\x42\x02\x10\x01\x12\r\n\x05saddr\x18\x07 \x03(\t\x12\x12\n\x06status\x18\x08 \x03(\x03\x42\x02\x10\x01\x12\n\n\x02rc\x18\t \x01(\x05\x12\n\n\x02\x62r\x18\n \x01(\x05\x12\x15\n\tdata_flag\x18\x0b \x03(\x05\x42\x02\x10\x01\"\x98\x02\n\x0bSysCommands\x12\x0c\n\x04port\x18\x01 \x01(\x05\x12\x17\n\x0bonline_rtus\x18\x02 \x03(\x03\x42\x02\x10\x01\x12\x15\n\tonline_id\x18\x03 \x03(\x05\x42\x02\x10\x01\x12\x15\n\tonline_ip\x18\x04 \x03(\x03\x42\x02\x10\x01\x12\x12\n\nlogger_msg\x18\x05 \x01(\t\x12\x35\n\x0bonline_info\x18\x06 \x03(\x0b\x32 .wlst.pb2.SysCommands.OnlineInfo\x1ai\n\nOnlineInfo\x12\n\n\x02ip\x18\x01 \x01(\x03\x12\x0f\n\x07members\x18\x02 \x03(\t\x12\x10\n\x08net_type\x18\x03 \x01(\x05\x12\x0e\n\x06signal\x18\x04 \x01(\x05\x12\x0e\n\x06phy_id\x18\x05 \x01(\x03\x12\x0c\n\x04imei\x18\x06 \x01(\x03\"W\n\x0bPassthrough\x12\x0f\n\x07\x63md_idx\x18\x01 \x01(\x05\x12\x11\n\tdata_mark\x18\x02 \x01(\x05\x12\x14\n\x08pkg_data\x18\x03 \x03(\x05\x42\x02\x10\x01\x12\x0e\n\x06status\x18\x04 \x01(\x05\x42\x02H\x01\x62\x06proto3')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_HEAD = _descriptor.Descriptor(
  name='Head',
  full_name='wlst.pb2.Head',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='mod', full_name='wlst.pb2.Head.mod', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='src', full_name='wlst.pb2.Head.src', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ver', full_name='wlst.pb2.Head.ver', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='tver', full_name='wlst.pb2.Head.tver', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='tra', full_name='wlst.pb2.Head.tra', index=4,
      number=5, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ret', full_name='wlst.pb2.Head.ret', index=5,
      number=6, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cmd', full_name='wlst.pb2.Head.cmd', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='code', full_name='wlst.pb2.Head.code', index=7,
      number=8, type=1, cpp_type=5, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='dst', full_name='wlst.pb2.Head.dst', index=8,
      number=9, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='base_addr', full_name='wlst.pb2.Head.base_addr', index=9,
      number=10, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='gid', full_name='wlst.pb2.Head.gid', index=10,
      number=11, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rcv', full_name='wlst.pb2.Head.rcv', index=11,
      number=12, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='idx', full_name='wlst.pb2.Head.idx', index=12,
      number=13, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='dt', full_name='wlst.pb2.Head.dt', index=13,
      number=15, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=34,
  serialized_end=229,
)


_ARGS = _descriptor.Descriptor(
  name='Args',
  full_name='wlst.pb2.Args',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ip', full_name='wlst.pb2.Args.ip', index=0,
      number=1, type=3, cpp_type=2, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='port', full_name='wlst.pb2.Args.port', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='addr', full_name='wlst.pb2.Args.addr', index=2,
      number=3, type=3, cpp_type=2, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='sim', full_name='wlst.pb2.Args.sim', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cid', full_name='wlst.pb2.Args.cid', index=4,
      number=5, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sims', full_name='wlst.pb2.Args.sims', index=5,
      number=6, type=3, cpp_type=2, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='saddr', full_name='wlst.pb2.Args.saddr', index=6,
      number=7, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='status', full_name='wlst.pb2.Args.status', index=7,
      number=8, type=3, cpp_type=2, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='rc', full_name='wlst.pb2.Args.rc', index=8,
      number=9, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='br', full_name='wlst.pb2.Args.br', index=9,
      number=10, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data_flag', full_name='wlst.pb2.Args.data_flag', index=10,
      number=11, type=5, cpp_type=1, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=232,
  serialized_end=412,
)


_SYSCOMMANDS_ONLINEINFO = _descriptor.Descriptor(
  name='OnlineInfo',
  full_name='wlst.pb2.SysCommands.OnlineInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='ip', full_name='wlst.pb2.SysCommands.OnlineInfo.ip', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='members', full_name='wlst.pb2.SysCommands.OnlineInfo.members', index=1,
      number=2, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='net_type', full_name='wlst.pb2.SysCommands.OnlineInfo.net_type', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='signal', full_name='wlst.pb2.SysCommands.OnlineInfo.signal', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='phy_id', full_name='wlst.pb2.SysCommands.OnlineInfo.phy_id', index=4,
      number=5, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='imei', full_name='wlst.pb2.SysCommands.OnlineInfo.imei', index=5,
      number=6, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=590,
  serialized_end=695,
)

_SYSCOMMANDS = _descriptor.Descriptor(
  name='SysCommands',
  full_name='wlst.pb2.SysCommands',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='port', full_name='wlst.pb2.SysCommands.port', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='online_rtus', full_name='wlst.pb2.SysCommands.online_rtus', index=1,
      number=2, type=3, cpp_type=2, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='online_id', full_name='wlst.pb2.SysCommands.online_id', index=2,
      number=3, type=5, cpp_type=1, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='online_ip', full_name='wlst.pb2.SysCommands.online_ip', index=3,
      number=4, type=3, cpp_type=2, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='logger_msg', full_name='wlst.pb2.SysCommands.logger_msg', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='online_info', full_name='wlst.pb2.SysCommands.online_info', index=5,
      number=6, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_SYSCOMMANDS_ONLINEINFO, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=415,
  serialized_end=695,
)


_PASSTHROUGH = _descriptor.Descriptor(
  name='Passthrough',
  full_name='wlst.pb2.Passthrough',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='cmd_idx', full_name='wlst.pb2.Passthrough.cmd_idx', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data_mark', full_name='wlst.pb2.Passthrough.data_mark', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pkg_data', full_name='wlst.pb2.Passthrough.pkg_data', index=2,
      number=3, type=5, cpp_type=1, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))),
    _descriptor.FieldDescriptor(
      name='status', full_name='wlst.pb2.Passthrough.status', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=697,
  serialized_end=784,
)

_SYSCOMMANDS_ONLINEINFO.containing_type = _SYSCOMMANDS
_SYSCOMMANDS.fields_by_name['online_info'].message_type = _SYSCOMMANDS_ONLINEINFO
DESCRIPTOR.message_types_by_name['Head'] = _HEAD
DESCRIPTOR.message_types_by_name['Args'] = _ARGS
DESCRIPTOR.message_types_by_name['SysCommands'] = _SYSCOMMANDS
DESCRIPTOR.message_types_by_name['Passthrough'] = _PASSTHROUGH

Head = _reflection.GeneratedProtocolMessageType('Head', (_message.Message,), dict(
  DESCRIPTOR = _HEAD,
  __module__ = 'protocol_head_pb2'
  # @@protoc_insertion_point(class_scope:wlst.pb2.Head)
  ))
_sym_db.RegisterMessage(Head)

Args = _reflection.GeneratedProtocolMessageType('Args', (_message.Message,), dict(
  DESCRIPTOR = _ARGS,
  __module__ = 'protocol_head_pb2'
  # @@protoc_insertion_point(class_scope:wlst.pb2.Args)
  ))
_sym_db.RegisterMessage(Args)

SysCommands = _reflection.GeneratedProtocolMessageType('SysCommands', (_message.Message,), dict(

  OnlineInfo = _reflection.GeneratedProtocolMessageType('OnlineInfo', (_message.Message,), dict(
    DESCRIPTOR = _SYSCOMMANDS_ONLINEINFO,
    __module__ = 'protocol_head_pb2'
    # @@protoc_insertion_point(class_scope:wlst.pb2.SysCommands.OnlineInfo)
    ))
  ,
  DESCRIPTOR = _SYSCOMMANDS,
  __module__ = 'protocol_head_pb2'
  # @@protoc_insertion_point(class_scope:wlst.pb2.SysCommands)
  ))
_sym_db.RegisterMessage(SysCommands)
_sym_db.RegisterMessage(SysCommands.OnlineInfo)

Passthrough = _reflection.GeneratedProtocolMessageType('Passthrough', (_message.Message,), dict(
  DESCRIPTOR = _PASSTHROUGH,
  __module__ = 'protocol_head_pb2'
  # @@protoc_insertion_point(class_scope:wlst.pb2.Passthrough)
  ))
_sym_db.RegisterMessage(Passthrough)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('H\001'))
_ARGS.fields_by_name['ip'].has_options = True
_ARGS.fields_by_name['ip']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_ARGS.fields_by_name['addr'].has_options = True
_ARGS.fields_by_name['addr']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_ARGS.fields_by_name['sims'].has_options = True
_ARGS.fields_by_name['sims']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_ARGS.fields_by_name['status'].has_options = True
_ARGS.fields_by_name['status']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_ARGS.fields_by_name['data_flag'].has_options = True
_ARGS.fields_by_name['data_flag']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_SYSCOMMANDS.fields_by_name['online_rtus'].has_options = True
_SYSCOMMANDS.fields_by_name['online_rtus']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_SYSCOMMANDS.fields_by_name['online_id'].has_options = True
_SYSCOMMANDS.fields_by_name['online_id']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_SYSCOMMANDS.fields_by_name['online_ip'].has_options = True
_SYSCOMMANDS.fields_by_name['online_ip']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
_PASSTHROUGH.fields_by_name['pkg_data'].has_options = True
_PASSTHROUGH.fields_by_name['pkg_data']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
# @@protoc_insertion_point(module_scope)
