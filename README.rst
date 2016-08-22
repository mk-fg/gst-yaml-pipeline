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

Example config (gst-yaml-pipeline.example.yaml)::

  ## Example:
  #
  # element-name: (value is optional, as is any keys in there)
  #
  #   name: # overrides element-name above
  #   plugin-name: # same as pre-/ element-name by default
  #
  #   link: # can be non-map value, to interpret as "down" option
  #     # "down" can be:
  #     #  - true - auto-link element to the next (downstream) one (default)
  #     #  - [src-pad-name>]dst-element-name[.dst-pad-name] (can be list)
  #     #  - false - don't link from this section
  #     down: true
  #     up: [dst-pad-name<]src-element-name[.src-pad-name] # pad(s) to add link(s) from (can be list)
  #     delayed: false # delay linking until pads will be available (for e.g. automagic stuff)
  #
  #   props:
  #     prop-name: prop-value

::

  ## Simple working pipeline:

  audiotestsrc:
  audioconvert:
  autoaudiosink:

::

  ## More complex rtp-streaming pipeline:

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

Invocation: ``./gst-yaml-pipeline.py --debug gst-yaml-pipeline.example.yaml``

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
