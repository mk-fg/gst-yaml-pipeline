gst-yaml-pipeline
=================

Python 3.x script to build GStreamer pipeline from YAML-ish
configuration file and run it.

Config format is not strictly YAML, as it preserves ordering in maps,
which regular YAML does not do.

::

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
