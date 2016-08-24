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

	def __iter__(self):
		key_set = dict.fromkeys(set().union(*self.maps), True)
		return filter(lambda k: key_set.pop(k, False), it.chain.from_iterable(self.maps))

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

str_or_list = lambda v: ([v] if not isinstance(
	v or list(), (types.GeneratorType, list, tuple) ) else list(v or list()))



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
		if self.graph and self.graph_init:
			self.graph.set_state(Gst.State.NULL)
		self.graph = None
		self.loop = None

	def __enter__(self):
		self.open()
		return self
	def __exit__(self, *err): self.close()
	def __del__(self): self.close()


	def create_link(self, a, b, pad_a=None, pad_b=None, delay=False, err_info=''):
		assert not delay, [a, b, pad_a, pad_b, err_info] # XXX: not implemented
		link_repr = '{}.{} -> {}.{}'.format(
			GObjRepr.fmt(a), pad_a or '(any)',
			GObjRepr.fmt(b), pad_b or '(any)' )
		self.log.debug('Link {}', link_repr)
		if a.link_pads(pad_a, b, pad_b): return
		err_dict = dmap(err_info or dict(), dict.fromkeys('dept'))
		if err_info:
			err_info = list()
			if err_dict.d: err_info.append('downstream' if err_dict.d else 'upstream')
			if err_dict.e: err_info.append('element: {}'.format(err_dict.e))
			if err_dict.p: err_info.append('plugin: {}'.format(err_dict.p))
			err_info = ' ({})'.format(', '.join(err_info))
		self.log.error('Failed to create link: {}{}', link_repr, err_info)
		err_t = 'link'
		if err_dict.t: err_t += '-{}'.format(err_dict.t)
		raise GstPipeError(err_t, err_dict.e, err_dict.p, a, pad_a, b, pad_b)


	def create_pipeline(self):
		self.graph, self.graph_init = Gst.Pipeline.new(self.name), False
		self.bus = self.graph.get_bus()
		self.bus.add_signal_watch()
		self.bus.connect('message', self.on_bus_msg)
		self.es, self.es_print_caps = dict(), list()
		self.create_pipe(self.conf, name=[self.name])
		self.log.debug('Created gst pipeline {!r} (elements: {})', self.name, len(self.es))
		self.graph_init = True


	def create_pipe(self, conf, e_link_ds=None, name=None):
		'''Create and link sub-assembly of sequential
			elements, including anything nested inside these.'''

		es_len0, ea, ab = len(self.es), None, None
		for e_name, p in conf.items():
			if not p: p = dict()

			### Create

			p_name = e_name.rsplit('/', 1)[0]
			if p.get('name'): e_name = p['name']
			self.log.debug('Creating new element: {}', e_name)
			if e_name in self.es:
				self.log.error('Duplicate name for element: {!r} (plugin: {})', e_name, p_name)
				raise GstPipeError('create-name', e_name, p_name)
			e = self.es[e_name] = Gst.ElementFactory.make(p_name, e_name)
			if not e:
				self.log.error('Failed to create element: {!r} (plugin: {})', e_name, p_name)
				raise GstPipeError('create', e_name, p_name)
			for k, v in (p.get('props') or dict()).items(): e.set_property(k, v)
			self.graph.add(e)
			eb, ea = e, e if not ea else ea

			### Link

			links = p.get('link') or True
			links = dmap(
				dmap(down=links) if not isinstance(links, Mapping) else links,
				dict(down=True, up=None, delayed=False) )
			# self.log.debug(
			# '[{}] Flat-linking parameters {} (downstream link: {})...',
			# e_name, links, GObjRepr.fmt(e_link_ds) )

			if e_link_ds:
				assert not links.delayed, [e_name, links] # XXX: not implemented
				self.create_link( e_link_ds, e, delay=links.delayed,
					err_info=dict(e=e_name, p=p_name, t='downstream') )
				e_link_ds = None

			if links.down is True: e_link_ds = e
			for pad_dir, swap, specs in [('>', False, links.down), ('<', True, links.up)]:
				if specs is True: continue
				for spec in str_or_list(specs):
					pad_a = pad_b = None
					if pad_dir in spec: pad_a, spec = spec.split('<', 1)
					if '.' in spec: spec, pad_b = spec.rsplit('.', 1)
					a, b = e, self.es[spec]
					if swap: (a, b), (pad_a, pad_b) = (b, a), (pad_b, pad_a)
					self.create_link( a, b, pad_a, pad_b, delay=links.delayed,
						err_info=dict(e=e_name, p=p_name, d=not swap, t='pads') )

			### Pads and their sub-pipes

			pads = p.get('pads', dict())
			for pad_name, pad in pads.items():
				link_ds, pipe_ends = self.create_pipe(
					pad.get('pipe', dict()), name=name + [e_name, pad_name] )
				link = pad.get('link') or 'auto'
				if link == 'auto': link = 'up' if re.search(r'([-_]|\b)sink([-_]|\b)', pad_name) else 'down'
				link = {'<': 'up', '>': 'down'}.get(link, link)
				if link == 'up':
					swap, a, pad_a, b, pad_b = True, e, pad_name, pipe_ends[1], None
				elif link == 'down':
					swap, a, pad_a, b, pad_b = False, e, pad_name, pipe_ends[0], None
				else:
					m = re.search(r'^([<>])([^.]*)(?:\.(.*))$', link)
					if not m: raise ValueError('Invalid pad-link spec: {!r}', link)
					a, pad_a, (swap, b, pad_b) = e, pad_name, m.groups()
					swap, b = '><'.index(swap), self.es[b] if b else pipe_ends[swap == '<']
				if swap: (a, b), (pad_a, pad_b) = (b, a), (pad_b, pad_a)
				self.create_link( a, b, pad_a, pad_b, delay=links.delayed,
					err_info=dict(e=e_name, p=p_name, d=not swap, t='pads') )

			pads = p.get('print_caps')
			if pads: self.es_print_caps.append((e, pads))

		if len(name) > 1:
			self.log.debug( 'Created sub-pipeline'
				' {!r} (elements: {})', '.'.join(name), len(self.es) - es_len0 )

		return e_link_ds, (ea, eb)


	def run(self):
		self.log.debug('Starting pipeline...')
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

		hook = getattr(self, 'on_bus_{}'.format(msg.t.replace('-', '_')), None)
		if callable(hook): hook(msg, msg_raw)


	def on_bus_error(self, msg, msg_raw):
		self.log.error( 'Stopping loop due to'
			' error: {} (src: {})', msg.gerror, GObjRepr.fmt(msg.src) )
		self.log.debug( 'Error debug info:'
			'\n{hr}\n{i}\n{hr}', i=(msg.debug or '').rstrip('\n'), hr='- '*25 )
		self.loop.quit()

	def on_bus_state_changed(self, msg, msg_raw):
		if not (msg.src == self.graph and msg.new == 'playing'): return

		for e, pads in self.es_print_caps:
			pads_linked = dict(
				(pad.get_pad_template().name_template, pad)
				for pad in e.iterate_pads() if pad.is_linked() )
			pads = sorted(str_or_list(pads) if pads is not True else pads_linked.keys())
			for pad in pads:
				if pad not in pads_linked:
					self.log.warning( 'Failed to get pas for {}.{} - pad is not linked, all'
						' linked pads for element: {}', e.get_name(), pad, ', '.join(pads_linked.keys()) )
					continue
				caps = pads_linked[pad].get_current_caps()
				self.log.info('Caps for {}.{}: {}', e.get_name(), pad, caps)



def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='App to build and run GStreamer (gst) pipeline from YAML config.')

	parser.add_argument('conf', nargs='?',
		help='YAML config with pipeline description. WIll be read from stdin, if omitted.')
	parser.add_argument('-n', '--name', metavar='name',
		default='yaml-pipe', help='Gst pipeline name (default: %(default)s).')

	parser.add_argument('-y', '--dry-run',
		action='store_true', help='Create pipeline and exit, instead of running it.')
	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = get_logger('main')

	src = sys.stdin if not opts.conf else open(opts.conf)
	try: conf = yaml_load(src, dmap)
	finally: src.close()

	with GstPipe(opts.name, conf) as pipe:
		if not opts.dry_run: pipe.run()

if __name__ == '__main__': sys.exit(main())
