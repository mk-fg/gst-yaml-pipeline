gst-yaml-pipeline
=================

Python 3.x script to build GStreamer pipeline from YAML-ish
configuration file and run it.

Config format is not strictly YAML, as it preserves ordering in maps,
which regular YAML does not do.


Usage
-----

Example config (gst-yaml-pipeline.example.yaml)::

  ## Example:
  #
  # plugin-name: (value is optional, as is any keys in there)
  #
  #   e: element-name (defaults to plugin-name)
  #   link-delayed: false
  #
  #   props:
  #     prop-name: prop-value

  ## Simple working pipeline:
  audiotestsrc:
  audioconvert:
  autoaudiosink:

Invocation: ``./gst-yaml-pipeline.py --debug gst-yaml-pipeline.example.yaml``

| Enable gst debug messages: ``GST_DEBUG='*:4' ./gst-yaml-pipeline.py ...``
| (see also "ENVIRONMENT VARIABLES" section in "man gst-launch-1.0")


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
