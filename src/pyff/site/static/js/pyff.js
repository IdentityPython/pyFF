/**
 * Created with PyCharm.
 * User: leifj
 * Date: 2/6/13
 * Time: 2:14 PM
 * To change this template use File | Settings | File Templates.
 */

(function( $ ) {
    if (!(window.console && console.log)) { (function() { var noop = function() {}; var methods = ['assert', 'clear', 'count', 'debug', 'dir', 'dirxml', 'error', 'exception', 'group', 'groupCollapsed', 'groupEnd', 'info', 'log', 'markTimeline', 'profile', 'profileEnd', 'markTimeline', 'table', 'time', 'timeEnd', 'timeStamp', 'trace', 'warn']; var length = methods.length; var console = window.console = {}; while (length--) { console[methods[length]] = noop; } }()); }

    function _autoselect() {
        var use_idp;
        use_idp = $.jStorage.get('pyff.discovery.idp');
        if (use_idp) {
            ds_select(use_idp);
        }
    }

    _autoselect();

    function ds_select(entityID) {
        var params;
        params = $.deparam.querystring();
        var qs;
        console.log(entityID);
        qs = params['return'].indexOf('?') === -1 ? '?' : '&';
        if ($('#remember').is(':checked')) {
            $.jStorage.set('pyff.discovery.idp',entityID);
        }
        var returnIDParam = params['returnIDParam'];
        if (! returnIDParam) {
            returnIDParam = "entityID";
        }
        window.location = params['return']+qs+returnIDParam+'='+entityID;
        return false;
    }

    function contains_idp(idp,lst) {
        for (var i = 0; i < lst.length; i++) {
            var item = lst[i];
            if (item['entityID'] == idp['entityID']) {
                return true;
            }
        }
        return false;
    }

    function addIdP(item) {
        var idps = $.jStorage.get('pyff.discovery.idps',[]);
        //console.log(item);
        if (!contains_idp(item,idps)) {
            idps.unshift(item);
        }
        while (idps.length > 3) {
            idps.pop()
        }
        $.jStorage.set('pyff.discovery.idps',idps);
        return ds_select(item['entityID']);
    }

    function find_idp(id,lst) {
        for (var i = 0; i < lst.length; i++) {
            if (id == lst[i]['entityID']) {
                return i
            }
        }
        return -1
    }

    function select_idp(id) {
        $.ajax({
            datatype: 'json',
            url: '/metadata/' + id + ".json",
            success: function (data) {
                for (var i = 0; i < data.length; i++) {
                    //console.log("fetched: "+data[i]);
                    return addIdP(data[i]);
                }
            }
        });
    }

    var methods;
    var seldiv;

    function sel2_focus() {
        seldiv.select2('focus');
    }

    function ta_focus() {
        seldiv.focus();
    }

    function use_select2() {
        return false;
        // return ! DetectTierIphone() && ! DetectTierTablet();
    }

    methods = {
        init: function (options) {
            this.each(function (opts) {
                seldiv = $(this);
                if (use_select2()) {
                    seldiv.change(function (ev) {
                        select_idp(ev['val'])
                    });
                    seldiv.select2({
                        placeholder: seldiv.attr('rel'),
                        ajax: {
                            url: seldiv.attr('data-target'),
                            data: function (term, page) {
                                return {
                                    query: term,
                                    page_limit: 10,
                                    page: page,
                                    paged: true,
                                    entity_filter: '{http://pyff-project.org/role}idp'
                                };
                            },
                            results: function (data, page) {
                                var more = (page * 10) < data['total'];
                                return {results: data['entities'], more: more}
                            }
                        },
                        formatResult: function(idp) {
                            //console.log(idp);
                            return idp['label']; //['label'];
                        },
                        formatSelection: function(idp) {
                            //console.log(idp);
                            return idp['value']; //['value'];
                        },
                        dropdownCssClass: 'bigdrop',
                        width: 'resolve'
                    });
                    methods['focus'] = sel2_focus;
                } else  {
                    seldiv.parent().prepend($('<em>').append(seldiv.attr('rel')));
                    seldiv.typeahead({
                        minLength: 2,
                        source: function(query,process) {
                            $.ajax(seldiv.attr('data-target'),
                                {
                                    data: {
                                            query: query.toLowerCase(),
                                            entity_filter: '{http://pyff-project.org/role}idp'
                                    }
                                }
                            ).done(
                                function(data) {
                                    var resultList = data.map(function (item) {
                                        var aItem = { id: item['id'], label: item['label'], value: item['value'] };
                                        return JSON.stringify(aItem);
                                    });
                                    process(resultList);
                                }
                            )
                        },
                        matcher: function(item) {
                            var o = JSON.parse(item);
                            return ~o['label'].toLowerCase().indexOf(this.query.toLowerCase())
                        },
                        sorter: function(items) {
                            var beginswith = [], caseSensitive = [], caseInsensitive = [], item;
                            var aItem
                            while (aItem = items.shift()) {
                                item = JSON.parse(aItem);
                                if (!item['label'].toLowerCase().indexOf(this.query.toLowerCase()))
                                    beginswith.push(JSON.stringify(item));
                                else if (~item['label'].indexOf(this.query))
                                    caseSensitive.push(JSON.stringify(item));
                                else
                                    caseInsensitive.push(JSON.stringify(item));
                            }
                            return beginswith.concat(caseSensitive, caseInsensitive)
                        },
                        highlighter: function (item) {
                            var o = JSON.parse(item);
                            var query = this.query.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, '\\$&');
                            return o['label'].replace(new RegExp('(' + query + ')', 'ig'), function ($1, match) {
                                return '<strong>' + match + '</strong>'
                            });
                        },
                        updater: function (item) {
                            var o = JSON.parse(item);
                            select_idp(o['id']);
                            seldiv.attr('value',o['value']);
                            return o['label'];
                        }
                    });
                    methods['focus'] = ta_focus;
                }

                $.each(options,function(key,val) {
                    seldiv.dsSelect(key,val);
                });
                seldiv.dsSelect('resize');
                seldiv.dsSelect('focus');
            });
            $("button.unselect").bind('click.ds', methods.unselect);
            $("a.select").bind('click.ds',methods.select);
        },
        resize: function() {
            var idps;
            idps = $.jStorage.get('pyff.discovery.idps');
            //console.log($(this));
            if (!idps || idps.length == 0) {
                seldiv.trigger('empty');
            } else {
                seldiv.trigger('nonempty');
            }
        },
        focus: function () {
            seldiv.focus();
        },
        empty: function (fn) {
            $(this).bind('empty',fn);
        },
        nonempty: function (fn) {
            $(this).bind('nonempty',fn);
        },
        unselect: function (e) {
            e.preventDefault();
            //e.stopPropagation();
            var id = $(this).attr('rel');
            var idps = $.jStorage.get('pyff.discovery.idps', []);
            var idx = find_idp(id, idps);
            if (idx != -1) {
                idps.splice(idx, 1);
                $.jStorage.set('pyff.discovery.idps', idps);
                $(this).parent().parent().remove();
                $(this).dsSelect('resize');
            }
        },
        select: function(e) {
            e.preventDefault();
            return ds_select($(this).attr('href'));
        }
    };

    $("img.fallback-icon").error(function(e) {
        $(this).error(function(e) {});
        $(this).attr('src','1x1t.png').removeClass("img-polaroid").hide();
    });

    $.fn.dsQuickLinks = function() {
        this.each(function() {
            var $this = $(this);
            $this.html($('<ul>').addClass("nav nav-tabs nav-stacked").append(function() {
                var item;
                var lst = $.jStorage.get('pyff.discovery.idps',[]);
                for (var i = 0; i < lst.length; i++) {
                    var item = lst[i];
                    var outer = $('<li>');
                    var idp = $('<a>').addClass("select").attr('href',item['entityID']);
                    var dismiss = $('<button>').attr('type',"button").addClass('close unselect').attr('rel',item['entityID']).append("&times;");
                    idp.append(dismiss);

                    idp.append($('<h4>').addClass("idp-label").append(item['title']));
                    if (item['icon']) {
                        idp.append($('<img>').attr('src',item['icon']).addClass("fallback-icon img-polaroid idp-icon"));
                    }

                    outer.append(idp);
                    $(this).append(outer);
                }
            }));
        });
    };

    $.fn.dsSelect = function(method) {
        if ( methods[method] ) {
            return methods[method].apply( this, Array.prototype.slice.call( arguments, 1 ));
        } else if ( typeof method === 'object' || ! method ) {
            return methods.init.apply( this, arguments );
        } else {
            $.error( 'Method ' +  method + ' does not exist on jQuery.dsSelect' );
        }
    };

    $.fn.dsRelyingParty = function(id) {
        var o = $(this);
        $.ajax({
            url: '/metadata/'+ id +'.json',
            type: 'json',
            success: function(data) {
                for (var i = 0; i < data.length; i++) {
                    var entity = data[i];
                    $(o).filter(".sp-icon").each(function() {
                        if (entity.icon) {
                            $(this).append($('img').attr('src',entity.icon))
                        }
                    });
                    $(o).filter(".sp-name").each(function() {
                        if (entity.title) {
                            $(this).append(entity.title)
                        }
                    });
                    $(o).filter(".sp-description").each(function() {
                        if (!entity.descr) {
                            entity.descr = "<em>No description available...</em>"
                        }
                        if (entity.descr) {
                            $(this).append(entity.descr).addClass("alert alert-info");
                        }
                    });
                }
            }
        });
    };
})( jQuery );