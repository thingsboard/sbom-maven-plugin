def log = new File(basedir, 'build.log').text
assert log.contains('No metadata configured: set at least one of manufacturer, supplier, componentManufacturer')
true
