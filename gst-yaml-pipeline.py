#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
from collections import ChainMap, Mapping, OrderedDict
import os, sys, logging, types, re, base64

import yaml

import gi
gi.require_version('Gst', '1.0')
from gi.repository import Gst, GObject, GLib


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

def b64(data):
	return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def get_uid_token(chars=4):
	assert chars * 6 % 8 == 0, chars
	return b64(os.urandom(chars * 6 // 8))

def log_lines(log_func, lines, log_func_last=False):
	if isinstance(lines, str): lines = list(line.rstrip() for line in lines.rstrip().split('\n'))
	uid = get_uid_token()
	for n, line in enumerate(lines, 1):
		if isinstance(line, str): line = '[{}] {}', uid, line
		else: line = ('[{}] {}'.format(uid, line[0]),) + line[1:]
		if log_func_last and n == len(lines): log_func_last(*line)
		else: log_func(*line)


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

	loop = graph = status = error = None
	conf_defaults = dmap(
		pipe=dict(name='yaml-pipe', info=None),
		e=dict(
			name=None, info=None, props=dict(), pads=dict(),
			link=dict(down=True, up=None, delay=False) ) )

	def __init__(self, conf, conf_pipe, loop=None):
		self.conf_pipe, self.conf = conf_pipe, dmap(conf, self.conf_defaults.pipe)
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


	def _create_link_cb( self,
			a, pad_new, pad_check, b, pad_b, caps, err_info, link_state ):
		if pad_check and pad_check != pad_new.get_pad_template().name_template:
			self.log.debug(
				'Skipping non-matching pad-added spec (link: {} -> {}): {} != {}',
				GObjRepr.fmt(a), GObjRepr.fmt(b), pad_new, pad_check )
			return
		self.log.debug( 'Delayed linking event'
			' for: {} (src pad: {})', err_info.l, pad_new.get_name() )
		link_args = link_state.pop('args', None)
		if link_args:
			a, b, pad_a, pad_b_old = link_args
			self.log.debug( 'Removing old link'
				' {} (pads: {} -> {})', err_info.l, pad_a, pad_b_old )
			a.unlink_pads(pad_a, b, pad_b_old)
		link_args = [a, b, pad_new.get_name(), pad_b]
		link_kws = dict(caps=caps, err_info=err_info)
		if not pad_b: # must be resolved here for later unlinking
			pad_b = b.get_compatible_pad(pad_new, caps)
			if pad_b: link_args[-1] = pad_b.get_name()
			else: link_kws['err_fake'] = True # no point trying it again there
		self.create_link(*link_args, **link_kws)
		link_state['args'] = link_args

	def create_link( self,
			a, b, pad_a=None, pad_b=None,
			delay=False, caps=None, err_info=None, err_fake=False ):
		'''delay - link pads on "pad-added" event.
			err_info - optional info to format error with - dict(
				e=element-name, p=plugin-name, t=optional error-suffix,
				d=optional True/False to add "downstream"/"upstream" ).
			err_fake - raise error without even trying to link.'''
		if isinstance(caps, str): caps = Gst.caps_from_string(caps.strip())
		err_info = dmap(dict(), err_info or dict(), dict.fromkeys('depth'))
		link_id = id(a), id(b), pad_a, pad_b
		if err_info.h != link_id:
			err_info.update( h=link_id,
				l='{}.{} -> {}.{}{}'.format(
					GObjRepr.fmt(a), pad_a or '(any)',
					GObjRepr.fmt(b), pad_b or '(any)',
					' [{}]'.format(caps.strip()) if caps else '' ) )
		if delay:
			a.connect( 'pad-added',
				self._create_link_cb, pad_a, b, pad_b, caps, err_info, dict() )
			return
		self.log.debug('New link: {}', err_info.l)
		if not err_fake and a.link_pads_filtered(pad_a, b, pad_b, caps): return
		err_t, err_ext = 'link', list()
		if err_info.d: err_ext.append('downstream' if err_info.d else 'upstream')
		if err_info.e: err_ext.append('element: {}'.format(err_info.e))
		if err_info.p: err_ext.append('plugin: {}'.format(err_info.p))
		if err_info.t: err_t += '-{}'.format(err_info.t)
		err_ext = ' ({})'.format(', '.join(err_ext)) if err_ext else ''
		self.log.error('Failed to create link: {}{}', err_info.l, err_ext)
		raise GstPipeError(err_t, err_dict.e, err_info.p, a, pad_a, b, pad_b, caps)


	def create_pipeline(self):
		self.graph, self.graph_init = Gst.Pipeline.new(self.conf.name), False
		self.bus = self.graph.get_bus()
		self.bus.add_signal_watch()
		self.bus.connect('message', self.on_bus_msg)
		self.es, self.es_info = dict(), dmap(caps=list())
		self.create_pipe(self.conf_pipe, name=[self.conf.name])
		info = 'gst pipeline {!r} (elements: {})'.format(self.conf.name, len(self.es))
		self.log.debug('Created {}', info)
		self.graph_init, self.status = True, 'Running {}'.format(info)


	def create_pipe(self, conf, e_link_ds=None, name=None):
		'''Create and link sub-assembly of sequential
			elements, including anything nested inside these.'''

		es_len0, ea, ab = len(self.es), None, None
		for e_name, p in conf.items():
			p = dmap(p or dict(), self.conf_defaults.e)

			### Create

			p_name = e_name.rsplit('/', 1)[0]
			if p.name: e_name = p.name
			self.log.debug('Creating new element: {}', e_name)
			if e_name in self.es:
				self.log.error('Duplicate name for element: {!r} (plugin: {})', e_name, p_name)
				raise GstPipeError('create-name', e_name, p_name)
			e = self.es[e_name] = Gst.ElementFactory.make(p_name, e_name)
			if not e:
				self.log.error('Failed to create element: {!r} (plugin: {})', e_name, p_name)
				raise GstPipeError('create', e_name, p_name)
			for k, v in p.props.items():
				if k == 'caps': v = Gst.caps_from_string(v.strip())
				e.set_property(k, v)
			self.graph.add(e)
			eb, ea = e, e if not ea else ea

			### Link

			links = p.link if isinstance(p.link, Mapping)\
				else dmap(self.conf_defaults.e.link, down=p.link)
			# self.log.debug(
			# '[{}] Flat-linking parameters {} (downstream link: {})...',
			# e_name, links, GObjRepr.fmt(e_link_ds) )

			if e_link_ds:
				self.create_link( e_link_ds, e, delay=links.delay,
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
					self.create_link( a, b, pad_a, pad_b, delay=links.delay,
						err_info=dict(e=e_name, p=p_name, d=not swap, t='pads') )

			### Pads and their sub-pipes

			for pad_name, pad in p.pads.items():
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
				delay = pad.get('link_delay') or (isinstance(pad_a, str) and '%' in pad_a)
				self.create_link( a, b, pad_a, pad_b, caps=pad.get('link_caps'),
					delay=delay, err_info=dict(e=e_name, p=p_name, d=not swap, t='pads') )

			### Element info

			info = str_or_list(p.info)
			if info:
				info_caps = list()
				for k in info:
					m = re.search(r'^caps(?:\.(.*))?$', k)
					if m:
						if isinstance(info_caps, list):
							k, m = None, m.group(1)
							if m: info_caps.append(m)
							else: info_caps = True
						continue
					if k: self.log.warning('Unrecognized "info" type for element {!r}: {}', e_name, k)
				if info_caps: self.es_info.caps.append((e, info_caps))

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
			ret_list_wrap = lambda args,ret: [ret] if len(args) == 1 else ret
			for k, args in dict(
					state_changed=('old', 'new', 'pending'),
					stream_status=('type', 'owner'),
					async_done=('running_time',),
					new_clock=('clock',),
					error=('gerror', 'debug'),
					stream_start=None, eos=None ).items():
				t = getattr(Gst.MessageType, k.upper())
				p[t] = (lambda msg: None) if not args else\
					( lambda msg,func='parse_{}'.format(k),args=args:
						(args, zip(args, ret_list_wrap(args, getattr(msg, func)()))) )
			def _bus_msg_parse(msg_raw):
				if msg_raw.type not in p: msg = dmap(raw=msg_raw)
				else:
					msg = p[msg_raw.type](msg_raw)
					msg_args, msg = msg if msg else [tuple(), dict()]
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
			attrs = msg.raw if attrs is None else\
				dict((k, GObjRepr.fmt(msg[k])) for k in attrs)
			self.log.debug(
				'Message [{m.t}]: {attrs} (src: {src})',
				m=msg, src=GObjRepr.fmt(msg.src), attrs=attrs )

		hook = getattr(self, 'on_bus_{}'.format(msg.t.replace('-', '_')), None)
		if callable(hook): hook(msg, msg_raw)


	def on_bus_eos(self, msg, msg_raw):
		self.log.debug('Stream playback finished, exiting...')
		self.loop.quit()

	def on_bus_error(self, msg, msg_raw):
		self.log.error( 'Stopping loop due to'
			' error: {} (src: {})', msg.gerror, GObjRepr.fmt(msg.src) )
		self.log.debug( 'Error debug info:'
			'\n{hr}\n{i}\n{hr}', i=(msg.debug or '').rstrip('\n'), hr='- '*25 )
		self.error = True
		self.loop.quit()

	def on_bus_state_changed(self, msg, msg_raw):
		if not (msg.src == self.graph and msg.new == 'playing'): return

		for e, pads in self.es_info.caps:
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

		info = str_or_list(self.conf.info)
		for k in info:
			if k == 'latency':
				lines = list()
				lines.append('Pipeline latency info (min/max seconds, "L" - live):')
				for e_name, e in sorted( (e.get_name(), e)
						for e in it.chain(self.es.values(), [self.graph]) ):
					q = Gst.Query.new_latency()
					res = e.query(q)
					if res:
						live, *lat_vals = q.parse_latency()
						lat_vals = list(lat_vals)
						for n, v in enumerate(lat_vals):
							if v == Gst.CLOCK_TIME_NONE: lat_vals[n] = 'none'
							else: lat_vals[n] /= Gst.SECOND
						lines.append(('[ {:<15s} ] {} {:.4f} / {}', e_name, ' L'[live], *lat_vals))
					else: print('[{}] query failed!'.format(e_name))
				log_lines(self.log.info, lines)



def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='App to build and run GStreamer (gst) pipeline from YAML config.')

	parser.add_argument('conf', nargs='?',
		help='YAML config with pipeline description. WIll be read from stdin, if omitted.')

	parser.add_argument('--systemd', action='store_true',
		help='Use systemd service notification/watchdog mechanisms, if available.')
	parser.add_argument('-y', '--dry-run',
		action='store_true', help='Create pipeline and exit, instead of running it.')
	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.INFO)
	log = get_logger('main')

	if opts.systemd:
		from systemd import daemon
		import time
		def sd_cycle(ts=None, status_init=None):
			if not sd_cycle.ready:
				daemon.notify('READY=1')
				sd_cycle.update_status(status_init or 'Started')
				sd_cycle.ready = True
			if sd_cycle.delay:
				if ts is None: ts = time.monotonic()
				delay = sd_cycle.ts_next - ts
				if delay <= 0:
					sd_cycle.ts_next += sd_cycle.delay
					if sd_cycle.wdt: daemon.notify('WATCHDOG=1')
			else: sd_cycle.ts_next = None
			return True
		sd_cycle.update_status = lambda status:\
			daemon.notify('STATUS={}'.format(status))
		sd_cycle.ts_next = time.monotonic()
		wd_pid, wd_usec = (os.environ.get(k) for k in ['WATCHDOG_PID', 'WATCHDOG_USEC'])
		if wd_pid and wd_pid.isdigit() and int(wd_pid) == os.getpid():
			wd_interval = float(wd_usec) / 2e6 # half of interval in seconds
			assert wd_interval > 0, wd_interval
			log.debug('Initializing systemd watchdog pinger with interval: {}s', wd_interval)
			sd_cycle.wdt, sd_cycle.delay = True, wd_interval
		else: sd_cycle.wdt, sd_cycle.delay = False, None
		sd_cycle.ready = False
	else: sd_cycle = None

	src = sys.stdin if not opts.conf else open(opts.conf)
	try:
		conf = yaml_load(src, dmap)
		conf_pipe = conf.pop('pipeline', None)
		if not conf_pipe: conf, conf_pipe = dmap(), conf
	except Exception as err:
		parser.error( 'Failed processing'
			' configuration file: [{}] {}'.format(err.__class__.__name__, err) )
	finally: src.close()

	loop, ev_hooks = GLib.MainLoop(), list()
	with GstPipe(conf, conf_pipe, loop=loop) as pipe:
		if sd_cycle and sd_cycle.wdt:
			ev_hooks.append(GLib.timeout_add(sd_cycle.delay * 1000, sd_cycle))
			sd_cycle(status_init=pipe.status)
		if not opts.dry_run: pipe.run()
		for src_id in ev_hooks: GLib.source_remove(src_id)
		return int(bool(pipe.error))

if __name__ == '__main__': sys.exit(main())
