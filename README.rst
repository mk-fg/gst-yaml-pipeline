gst-yaml-pipeline
=================

Python 3.x script to build GStreamer pipeline from YAML-ish configuration file
and run it.

YAML can be more convenient for editing and version-control than messy
gst-launch pipelines, allows for comments and basic templating and should be
more readable.

Config format is not strictly YAML though, as it preserves ordering in maps,
which regular YAML does not do.

Script can also be used as a template for adding python app-specific logic on
top of configurable pipeline.


Usage
-----

See example config file ``gst-yaml-pipeline.example.yaml`` for detailed
format/structure description.

Examples:

* Simple flat pipeline::

    audiotestsrc:
    audioconvert:
    autoaudiosink:

  Here all elements are linked source-to-sink in same order as they're
  specified, with no extra properties configured.

* More complex nested rtp-streaming pipeline::

    rtpbin:
      pads:
        send_rtp_sink_0:
          pipe:
            audiotestsrc:
            vorbisenc:
            rtpvorbispay:
        recv_rtcp_sink_0: # rtcp feedback from client(s)
          pipe:
            udpsrc/rtcp:
              props:
                port: 5007
        send_rtp_src_0:
          pipe:
            udpsink/rtp:
              props:
                # host: localhost
                port: 5002
        send_rtcp_src_0:
          pipe:
            udpsink/rtcp:
              props:
                # host: localhost
                port: 5003
                sync: false
                async: false

  A tree with "rtpbin" pads connected to audio source/encoding pipeline and UDP
  inputs/outputs, each with their respective configuration.

  Note that format/structure of stuff under "pipe:" follows exactly same rules
  as top-level config, just gets linked to pad which it's defined under in the end.

* Exactly same pipeline as above, but flattened::

    rtpbin:
      link: false

    audiotestsrc:
    vorbisenc:
    rtpvorbispay:
      link: rtpbin.send_rtp_sink_0

    udpsink/rtp:
      props:
        # host: localhost
        port: 5002
      link:
        up: rtpbin.send_rtp_src_0
        down: false

    udpsink/rtcp:
      props:
        # host: localhost
        port: 5003
        sync: false
        async: false
      link:
        up: rtpbin.send_rtcp_src_0
        down: false

    udpsrc/rtcp:
      props:
        port: 5007
      link: rtpbin.recv_rtcp_sink_0

  Demonstrates linking in arbitrary (non-linear and non-nested) fashion between
  any elements.

Invocation: ``./gst-yaml-pipeline.py --debug my-pipeline.yaml``

| Enable gst debug messages: ``GST_DEBUG='*:4' GST_DEBUG_NO_COLOR=1 ./gst-yaml-pipeline.py ...``
| (see also ``ENVIRONMENT VARIABLES`` section in ``man gst-launch-1.0``)


Requirements
------------

* Python 3.x
* PyYAML
* Gstreamer 1.0+ with GObject-Introspection (gi, gir) python bindings.

Debian (plugins and such are optional)::

  # alias apt='apt --no-install-recommends'

  # apt install gstreamer1.0-tools
  # apt install python3 python3-yaml
  # apt install python3-gst-1.0 gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0

  # apt install gstreamer1.0-alsa gstreamer1.0-plugins-{base,good,bad}
  # apt install gir1.2-gst-plugins-base-1.0
