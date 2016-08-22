#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
from collections import ChainMap, Mapping, OrderedDict
import os, sys, logging, types, re

import yaml

import gi
gi.require_version('Gst', '1.0')
from gi.repository import Gst, GObject


class LogMessage(object):
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self): return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt

class LogStyleAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None):
		super(LogStyleAdapter, self).__init__(logger, extra or {})
	def log(self, level, msg, *args, **kws):
		if not self.isEnabledFor(level): return
		log_kws = {} if 'exc_info' not in kws else dict(exc_info=kws.pop('exc_info'))
		msg, kws = self.process(msg, kws)
		self.logger._log(level, LogMessage(msg, args, kws), (), log_kws)

get_logger = lambda name: LogStyleAdapter(logging.getLogger(name))


class GObjRepr(object):
	_re = re.compile(r'^<.*\((.*?) at 0x(\S+)\)>$')
	def __init__(self, m): self.m = m
	def __repr__(self): return '<{} {}>'.format(*self.m.groups())
	@classmethod
	def fmt(cls, gobj):
		if not isinstance(gobj, GObject.Object): return gobj
		m = cls._re.search(str(gobj))
		return gobj if not m else cls(m)


def yaml_load(stream, dict_cls=OrderedDict, loader_cls=yaml.SafeLoader):
	class CustomLoader(loader_cls): pass
	def construct_mapping(loader, node):
		loader.flatten_mapping(node)
		return dict_cls(loader.construct_pairs(node))
	CustomLoader.add_constructor(
		yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping )
	return yaml.load(stream, CustomLoader)


class dmap(ChainMap):

	maps = None

	def __init__(self, *maps, **map0):
		maps = list((v if not isinstance( v,
			(types.GeneratorType, list, tuple) ) else OrderedDict(v)) for v in maps)
		if map0 or not maps: maps = [map0] + maps
		super(dmap, self).__init__(*maps)

	def __repr__(self):
		return '<{} {:x} {}>'.format(
			self.__class__.__name__, id(self), repr(self._asdict()) )

	def _asdict(self):
		items = dict()
		for k, v in self.items():
			if isinstance(v, self.__class__): v = v._asdict()
			items[k] = v
		return items

	def _set_attr(self, k, v):
		self.__dict__[k] = v

	def __getitem__(self, k):
		k_maps = list()
		for m in self.maps:
			if k in m:
				if isinstance(m[k], Mapping): k_maps.append(m[k])
				elif not (m[k] is None and k_maps): return m[k]
		if not k_maps: raise KeyError(k)
		return self.__class__(*k_maps)

	def __getattr__(self, k):
		try: return self[k]
		except KeyError: raise AttributeError(k)

	def __setattr__(self, k, v):
		for m in map(op.attrgetter('__dict__'), [self] + self.__class__.mro()):
			if k in m:
				self._set_attr(k, v)
				break
		else: self[k] = v

	def __delitem__(self, k):
		for m in self.maps:
			if k in m: del m[k]


class GstPipeError(Exception): pass

class GstPipe(object):

	loop = graph = None

	def __init__(self, name, conf, loop=None):
		self.name, self.conf = name, conf
		self.loop = loop or GObject.MainLoop()
		self.log = get_logger('gst.pipe')


	def open(self):
		GObject.threads_init()
		Gst.init(None)
		self.create_pipeline()

	def close(self):
		if self.graph:
			self.graph.set_state(Gst.State.NULL)
			self.graph = None
		if self.loop:
			self.loop = None

	def __enter__(self):
		self.open()
		return self
	def __exit__(self, *err): self.close()
	def __del__(self): self.close()


	def create_pipeline(self):
		g = self.graph = Gst.Pipeline.new(self.name)

		self.bus = g.get_bus()
		self.bus.add_signal_watch()
		self.bus.connect('message', self.on_bus_msg)
		# self.bus.enable_sync_message_emission()
		# self.bus.connect('sync-message', self.on_bus_msg)

		def link_pad_delayed(b, a, pad):
			pad_dst = b.get_compatible_pad(pad, pad.get_caps())
			if not pad_dst: raise GstPipeError(b, a, pad)
			pad.link(pad_dst)

		e_last, n = None, 0
		for p_name, p in self.conf.items():
			if not p: p = dict()

			# Create
			e_name = p.get('e') or p_name
			e = Gst.ElementFactory.make(p_name, e_name)
			for k, v in (p.get('props') or dict()).items(): e.set_property(k, v)
			g.add(e)

			# Link
			if e_last is not None:
				if p.get('link-delayed'):
					e_last.connect('pad-added', ft.partial(link_pad_delayed, e))
				else: e_last.link(e)
			e_last, n = e, n + 1

		self.log.debug('Created gst pipeline {!r} ({} elements)', self.name, n)


	def run(self):
		self.graph.set_state(Gst.State.PLAYING)
		self.log.debug('Entering GLib loop...')
		self.loop.run()
		self.log.debug('Finished')


	_bus_msg_parse = None

	def on_bus_msg(self, bus, msg_raw):
		if not self._bus_msg_parse:
			p = dict()
			for k, args in dict(
					state_changed=('old', 'new', 'pending'),
					stream_status=('type', 'owner'),
					error=('gerror', 'debug'), eos=None ).items():
				t = getattr(Gst.MessageType, k.upper())
				p[t] = (lambda msg: None) if not args else\
					( lambda msg,func='parse_{}'.format(k),args=args:
						(args, zip(args, getattr(msg, func)())) )
			def _bus_msg_parse(msg_raw):
				if msg_raw.type not in p: msg = dmap(raw=msg_raw)
				else:
					msg_args, msg = p[msg_raw.type](msg_raw)
					msg = dmap((k, v if not isinstance( v,
						GObject.GEnum ) else v.value_nick) for k, v in msg)
					msg._set_attr('_args', msg_args)
				msg.t, msg.src = msg_raw.type.first_value_nick, msg_raw.src
				msg.seq, msg.ts = msg_raw.seqnum, msg_raw.timestamp
				return msg
			self._bus_msg_parse = _bus_msg_parse
		msg = self._bus_msg_parse(msg_raw)
		if self.log.isEnabledFor(logging.DEBUG): # to avoid formatting stuff
			attrs = getattr(msg, '_args', None)
			attrs = dict((k, GObjRepr.fmt(msg[k])) for k in attrs) if attrs else msg.raw
			self.log.debug(
				'Message [{m.t}]: {attrs} (src: {src})',
				m=msg, src=GObjRepr.fmt(msg.src), attrs=attrs )


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='App to build and run GStreamer (gst) pipeline from YAML config.')

	parser.add_argument('conf', nargs='?',
		help='YAML config with pipeline description. WIll be read from stdin, if omitted.')
	parser.add_argument('-n', '--name', metavar='name',
		default='yaml-pipe', help='Gst pipeline name (default: %(default)s).')

	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = get_logger('main')

	src = sys.stdin if not opts.conf else open(opts.conf)
	try: conf = yaml_load(src, dmap)
	finally: src.close()

	with GstPipe(opts.name, conf) as pipe: pipe.run()


if __name__ == '__main__': sys.exit(main())
