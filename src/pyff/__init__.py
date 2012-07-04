import sys
import getopt
import os
import hashlib
import lxml.etree as etree
from pyff.feed import import_feed
from pyff.utils import resource_string
from pyff.mdrepo import NS,MDRepository

def process(fn,md,stdout):
    """
    Load one feed specifier and process it
    """
    feed = import_feed(fn)
    name = feed.get('Name',fn)

    for u in feed.get('inputs',[]):
        if type(u) is dict:
            url = u.get('url',None)
            if url is not None and (url.startswith("http://") or url.startswith("https:") or url.startswith("ftp://")):
                md.load_url(url,md,verify=u.get('verify',None))
            else:
                raise Exception,"Unknown metadata input format: %s" % u
        elif os.path.isdir(u):
            md.load_dir(u,md)
        else:
            raise Exception,"Unknown metadata input: %s" % u

    t = md.entity_set(md,feed.get('entities',md.keys()),name,feed.get('cacheDuration',None),feed.get('validUntil',None))
    for ts in feed.get('pipeline',[]):
        # apply an xslt stylesheet
        stylesheet = ts.pop('stylesheet',None)
        if stylesheet is not None:
            xslt = etree.parse(resource_string(stylesheet,"xslt"))
            transform = etree.XSLT(xslt)
            # this is to make sure the parameters are passed as xslt strings
            d = dict((k,"\'%s\'" % v) for (k,v) in ts.items())
            ot = transform(t,**d)
            t = ot
            # split into EntityDescriptor-parts and save in target_dir/sha1(@entityID).xml
        target_dir = ts.pop('store',None)
        if target_dir is not None:
            if not os.path.isdir(target_dir):
                os.makedirs(target_dir)
            for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
                eid = e.get('entityID')
                if eid is None or len(eid) == 0:
                    raise Exception,"Missing entityID in %s" % e
                m = hashlib.sha1()
                m.update(eid)
                d = m.hexdigest()
                with open("%s.xml" % os.path.join(target_dir,d),"w") as fn:
                    fn.write(etree.tostring(e,encoding='UTF-8',xml_declaration=True,pretty_print=True))
            # sign
        key_name = ts.pop("sign",None)
        if key_name is not None:
            # TODO sign
            #t = ot
            pass
            # write to file
        output_file = ts.pop("publish",None)
        if output_file is not None:
            out = output_file
            if os.path.isdir(output_file):
                out = os.path.join(output_file,os.path.splitext(fn)[0])
            with open(out,"w") as fo:
                fo.write(etree.tostring(t,encoding='UTF-8',xml_declaration=True,pretty_print=True))
            # print entityIDs on stdout
        if ts.has_key('showeids'):
            for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
                print e.get('entityID')


    md[name] = t

def main():
    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    # process options

    md=MDRepository()
    for o, a in opts:
        if o in ("-h", "--help"):
            print __doc__
            sys.exit(0)

    # process arguments

    for arg in args:
        process(arg,md)

if __name__ == "__main__":
    main()