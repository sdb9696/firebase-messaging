# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: android_checkin.proto
# Protobuf Python Version: 6.30.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    6,
    30,
    2,
    '',
    'android_checkin.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15\x61ndroid_checkin.proto\x12\rcheckin_proto\"\x8a\x03\n\x10\x43hromeBuildProto\x12:\n\x08platform\x18\x01 \x01(\x0e\x32(.checkin_proto.ChromeBuildProto.Platform\x12\x16\n\x0e\x63hrome_version\x18\x02 \x01(\t\x12\x38\n\x07\x63hannel\x18\x03 \x01(\x0e\x32\'.checkin_proto.ChromeBuildProto.Channel\"}\n\x08Platform\x12\x10\n\x0cPLATFORM_WIN\x10\x01\x12\x10\n\x0cPLATFORM_MAC\x10\x02\x12\x12\n\x0ePLATFORM_LINUX\x10\x03\x12\x11\n\rPLATFORM_CROS\x10\x04\x12\x10\n\x0cPLATFORM_IOS\x10\x05\x12\x14\n\x10PLATFORM_ANDROID\x10\x06\"i\n\x07\x43hannel\x12\x12\n\x0e\x43HANNEL_STABLE\x10\x01\x12\x10\n\x0c\x43HANNEL_BETA\x10\x02\x12\x0f\n\x0b\x43HANNEL_DEV\x10\x03\x12\x12\n\x0e\x43HANNEL_CANARY\x10\x04\x12\x13\n\x0f\x43HANNEL_UNKNOWN\x10\x05\"\xf6\x01\n\x13\x41ndroidCheckinProto\x12\x19\n\x11last_checkin_msec\x18\x02 \x01(\x03\x12\x15\n\rcell_operator\x18\x06 \x01(\t\x12\x14\n\x0csim_operator\x18\x07 \x01(\t\x12\x0f\n\x07roaming\x18\x08 \x01(\t\x12\x13\n\x0buser_number\x18\t \x01(\x05\x12:\n\x04type\x18\x0c \x01(\x0e\x32\x19.checkin_proto.DeviceType:\x11\x44\x45VICE_ANDROID_OS\x12\x35\n\x0c\x63hrome_build\x18\r \x01(\x0b\x32\x1f.checkin_proto.ChromeBuildProto*g\n\nDeviceType\x12\x15\n\x11\x44\x45VICE_ANDROID_OS\x10\x01\x12\x11\n\rDEVICE_IOS_OS\x10\x02\x12\x19\n\x15\x44\x45VICE_CHROME_BROWSER\x10\x03\x12\x14\n\x10\x44\x45VICE_CHROME_OS\x10\x04\x42\x02H\x03')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'android_checkin_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'H\003'
  _globals['_DEVICETYPE']._serialized_start=686
  _globals['_DEVICETYPE']._serialized_end=789
  _globals['_CHROMEBUILDPROTO']._serialized_start=41
  _globals['_CHROMEBUILDPROTO']._serialized_end=435
  _globals['_CHROMEBUILDPROTO_PLATFORM']._serialized_start=203
  _globals['_CHROMEBUILDPROTO_PLATFORM']._serialized_end=328
  _globals['_CHROMEBUILDPROTO_CHANNEL']._serialized_start=330
  _globals['_CHROMEBUILDPROTO_CHANNEL']._serialized_end=435
  _globals['_ANDROIDCHECKINPROTO']._serialized_start=438
  _globals['_ANDROIDCHECKINPROTO']._serialized_end=684
# @@protoc_insertion_point(module_scope)
