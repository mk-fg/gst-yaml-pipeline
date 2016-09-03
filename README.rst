gst-yaml-pipeline
=================

Python 3.x script to build GStreamer_ pipeline from YAML-ish
configuration file and run it.

Can be thought of as an alternative to gst-launch, which uses YAML_ config,
instead of long list of arguments on the command line.

YAML can be more convenient for editing and version-control than messy
gst-launch pipelines, allows for comments and basic templating and should be
more readable.

Config format is not strictly YAML though, as it preserves ordering in maps,
which regular YAML does not do.

Script can also be used as a template for adding python app-specific logic on
top of configurable pipeline.

.. _GStreamer: http://gstreamer.freedesktop.org/
.. _YAML: https://en.wikipedia.org/wiki/YAML

|

.. contents::
  :backlinks: none


Usage
-----

Script reads configuration file, builds GStreamer pipeline according to it,
and then - unless -y/--dry-run option is specified - runs it.

See example config file ``gst-yaml-pipeline.example.yaml`` for detailed
format/structure description.

Examples:

* Simple flat pipeline::

    audiotestsrc:
    audioconvert:
    autoaudiosink:

  Here all elements are linked source-to-sink in same order as they're
  specified, with no extra properties configured.

* More complex nested rtp-streaming pipeline (see `rtpbin docs`_)::

    rtpbin:
      pads:
        send_rtp_sink_0:
          pipe:
            audiotestsrc:
            opusenc:
            rtpopuspay:
        recv_rtcp_sink_0: # rtcp feedback from receiver(s)
          pipe:
            udpsrc/rtcp:
              props:
                port: 5007
        send_rtp_src_0:
          pipe:
            udpsink/rtp:
              props:
                # host: 224.0.0.56
                port: 5002
              info: caps # will print caps to be used on receiver(s)
        send_rtcp_src_0:
          pipe:
            udpsink/rtcp:
              props:
                port: 5003
                sync: false
                async: false

  A tree with "rtpbin" pads connected to audio source/encoding pipeline and UDP
  inputs/outputs, each with their respective configuration.

  Note that format/structure of stuff under "pipe:" follows exactly same rules
  as top-level config, just gets linked to pad which it's defined under in the end.

  .. _rtpbin docs: https://gstreamer.freedesktop.org/data/doc/gstreamer/head/gst-plugins-good-plugins/html/gst-plugins-good-plugins-rtpbin.html#gst-plugins-good-plugins-rtpbin.description

* Exactly same pipeline as above, but flattened::

    rtpbin:
      link: false

    audiotestsrc:
    opusenc:
    rtpopuspay:
      link: rtpbin.send_rtp_sink_0

    udpsrc/rtcp:
      props:
        port: 5007
      link: rtpbin.recv_rtcp_sink_0

    udpsink/rtp:
      props:
        port: 5002
      link:
        up: rtpbin.send_rtp_src_0
        down: false
      info: caps

    udpsink/rtcp:
      props:
        port: 5003
        sync: false
        async: false
      link:
        up: rtpbin.send_rtcp_src_0
        down: false

  Demonstrates linking in arbitrary (non-linear and non-nested) fashion between
  any elements.

* Pipeline and script parameters::

    name: my-file-player-pipeline
    info: latency # will print latency for elements and pipeline itself

    pipeline:
      filesrc:
        props:
          location: test.mp3
      decodebin: # will create src pad only upon getting first data
      alsasink: {link: {delay: true}}

Again, see more examples (and format/structure info) in ``gst-yaml-pipeline.example.yaml``.

Running the thing: ``./gst-yaml-pipeline.py --debug my-pipeline.yaml``

| Enable gst debug messages: ``GST_DEBUG='*:4' GST_DEBUG_NO_COLOR=1 ./gst-yaml-pipeline.py ...``
| (see also ``ENVIRONMENT VARIABLES`` section in ``man gst-launch-1.0``)

To run such pipeline on a more permanent basis from systemd unit::

  [Service]
  Type=notify
  User=gst-pipe
  ExecStart=/srv/gst-pipe/gst-yaml-pipeline --systemd /gst-pipe/pipeline.yaml

  WatchdogSec=90
  Restart=on-failure
  RestartSec=3
  StartLimitInterval=8min
  StartLimitBurst=10

  Environment=GST_DEBUG=*:3
  Environment=GST_DEBUG_NO_COLOR=1

(requires python-systemd_ module for --systemd option to work)

.. _python-systemd: https://github.com/systemd/python-systemd


Requirements
------------

* Python 3.x
* PyYAML_
* GStreamer_ 1.0+ with GObject-Introspection (gi, gir) python bindings.
* (optional) python-systemd_ - only when --systemd option is used

To install required deps on Debian-likes::

  # alias apt='apt --no-install-recommends'

  # apt install gstreamer1.0-tools
  # apt install python3 python3-yaml python3-gi
  # apt install python3-gst-1.0 gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0

  # apt install gstreamer1.0-alsa gstreamer1.0-plugins-{base,good}
  # apt install gir1.2-gst-plugins-base-1.0

Arch Linux::

  # pacman -S gstreamer gst-plugins-{base,good} python python-yaml gst-python

In install lines above, plugins and such are optional, though "gst-plugins-bad"
might also be needed for "rtpopusdepay" in ``gst-yaml-pipeline.example.yaml``.

.. _PyYAML: http://pyyaml.org/
