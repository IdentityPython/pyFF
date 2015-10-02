/**
 * Created with PyCharm.
 * User: leifj
 * Date: 2/6/13
 * Time: 2:14 PM
 * To change this template use File | Settings | File Templates.
 */

$(document).ready(function() {
    // send the user directly to the pre-selected idp if that setting exists

    function _autoselect() {
        var use_idp;
        use_idp = $.jStorage.get('pyff.discovery.idp');
        if (use_idp) {
            discovery_response(use_idp);
        }
    }

    function sha1_id(entityID) {
        return "{sha1}"+SHA1(entityID);
    }

    function _convert_local_store_fmt() {
        var lst = $.jStorage.get('pyff.discovery.idps',[]);
        for (var i = 0; i < lst.length; i++) {
            if ($.type(lst[i]) == 'string') {
            } else {
                lst[i] = lst[i].entityID;
            }
        }
        $.jStorage.set('pyff.discovery.idps',lst);
    }

    _convert_local_store_fmt();
    _autoselect();

    function _clone(o) {
        return jQuery.extend({},o);
    }

    function cancel_confirm() {
        window.location.reload();
    }

    function ds_confirm_select(item) {
        $('.idpchooser').hide();
        item.sticky = true;
        item.save = true;
        item.proceed = true;
        $(".confirm").html(idp_template.render(item));
        $('#proceed').attr("data-href", item['entityID']);
        $('#proceed_and_remember').attr("data-href", item['entityID']);
        if ($('#never-remember-selection-again').is(':checked')) {
            $.jStorage.set('pyff.discovery.allow_confirm', false);
        }
        $('#remember-selection-dlg').removeClass('hidden').show();
    }

    function discovery_response(entityID) {
        var idps = $.jStorage.get('pyff.discovery.idps', []);
        //console.log(idps);
        //console.log(entityID);
        if ($.inArray(entityID, idps) != -1) {

        } else {
            idps.unshift(entityID);
        }
        //console.log(idps);
        while (idps.length > 3) {
            idps.pop()
        }
        $.jStorage.set('pyff.discovery.idps', idps);

        var params;
        params = $.deparam.querystring();
        var qs;
        //console.log(entityID);
        if (params['return']) {
            qs = params['return'].indexOf('?') === -1 ? '?' : '&';
            var returnIDParam = params['returnIDParam'];
            if (!returnIDParam) {
                returnIDParam = "entityID";
            }
            window.location = params['return'] + qs + returnIDParam + '=' + entityID;
        }
        return false;
    }

    function with_entity_id(entityID, func, fail_func) {
        //console.log("with entity id "+entityID);
        with_id(sha1_id(entityID), func, fail_func);
    }

    var cache_time = 60 * 10 * 1000; /* 10 minutes in milliseconds */

    function with_id(id, func, fail_func) {
        //console.log("with_id "+id);
        var cached = $.jStorage.get(id);
        if (cached) {
            console.log($.jStorage.getTTL(id));
            if ($.jStorage.getTTL(id) <= 0 || $.jStorage.getTTL(id) > cache_time) {
                $.jStorage.setTTL(id, cache_time);
            }
            //console.log($.jStorage.getTTL(id));
            //console.log("cached...");
            //console.log(cached);
            func(_clone(cached));
        } else {
            //console.log('GET /metadata/' + id + ".json");
            $.ajax({
                datatype: 'json',
                url: '/metadata/' + id + ".json"
            }).done(function (data) {
                if ($.isArray(data)) {
                    for (var i = 0; i < data.length; i++) {
                        //console.log("fetched: ");
                        //console.log(data[i]);
                        $.jStorage.set(id,_clone(data[i]));
                        $.jStorage.setTTL(id, cache_time);
                        //console.log($.jStorage.getTTL(id));
                        func(data[i]);
                    }
                } else {
                    //console.log("got: ");
                    //console.log(data);
                    $.jStorage.set(id,_clone(data));
                    $.jStorage.setTTL(id, cache_time);
                    func(data);
                }
            }).fail(function () {
                $.jStorage.deleteKey(id);
                if (typeof fail_func !== 'undefined') {
                    fail_func(id);
                }
            });
        }
    }

    function select_idp(id) {
        with_entity_id(id, ds_confirm_select);
    }

    function cmp_title(a,b) {
        if (a.title == b.title){
            return 0;
        }
        return a.title > b.title ? 1 : -1;
    }

    var match_template = Hogan.compile('<div><p>{{title}}</br><small>{{descr}}</small></p></div>');
    var match_template_icon = Hogan.compile('<div><ul class="list-inline"><li>{{title}}<br/><small>{{descr}}</small></li>' +
        '{{#icon}}<li class="pull-right xs-hidden">' +
        '<img class="img-responsive img-thumbnail fallback-icon img-small" src="{{icon}}"/>' +
        '</li>{{/icon}}</ul></div>');
    var methods = {
        init: function (options) {
            this.filter('input').each(function (opts) {
                var seldiv = $(this);
                var uri = seldiv.attr('data-target');
                var related = seldiv.attr('data-related');
                //console.log(related);
                var remote = uri+"?query=%QUERY&entity_filter={http://macedir.org/entity-category}http://pyff.io/category/discoverable";
                if (related) {
                    remote = remote + "&related="+related
                }
                var engine = new Bloodhound({
                    name: 'idps',
                    limit: 50,
                    remote: remote,
                    datumTokenizer: Bloodhound.tokenizers.obj.whitespace('title'),
                    queryTokenizer: Bloodhound.tokenizers.whitespace
                });
                engine.initialize().done(function() {
                    seldiv.typeahead({
                            hint: true,
                            highlight: true,
                            minLength: 2
                        },
                        {
                            name: 'idps',
                            source: engine.ttAdapter(),
                            displayKey: 'title',
                            templates: {
                                suggestion: function(o) {
                                    return match_template.render(o)
                                }
                            }
                        }
                    )
                });
                seldiv.bind('typeahead:selected',function(event,entity) {
                    if (entity) {
                        //console.log("selected "+entity.entity_id);
                        select_idp(entity.entity_id);
                    }
                });
                $.each(options,function(key,val) {
                    seldiv.dsSelect(key,val);
                });
                $('body').on('vclick.ds', 'button.unselect', methods.unselect);
                $('body').on('vclick.ds', '.select', methods.select);
                $('body').on('vclick.ds', '.proceed', methods.proceed);
                $('body').on('vclick.ds', '.proceed', methods.proceed);
                $('body').on('vclick.ds', '.remember', methods.remember);
                $('body').on('vclick.ds', '.proceed_and_remember', methods.proceed_and_remember);
                $('body').on('vclick.ds', '.cancel', cancel_confirm);
            });
            this.filter('select').each(function (opts) {
                var seldiv = $(this);
                seldiv.change(function(opt) {
                    select_idp(seldiv.find('option:selected').attr('value')); // TODO - fix id in xsltjson xslt
                });
                $.each(options,function(key,val) {
                    seldiv.dsSelect(key,val);
                });
            });
        },
        reset: function() {
            $(this).filter('input').each(function () {
                $(this).typeahead('val','');
                $(this).focus();
            });
        },
        refresh: function() {
            this.filter('select').each(function() {
                var seldiv = $(this);
                var uri = seldiv.attr('data-target');
                seldiv.html($('<option>').attr('value','').append($('<em>').append(seldiv.attr('title'))))
                $.getJSON(uri, function (data) {
                    $.each($(data).sort(cmp_title),function(pos,elt) {
                        //console.log(elt);
                        seldiv.append($('<option>').attr('value',elt.entityID).append(elt.title));
                    })
                });
            });
        },
        remember: function (e) {
            e.preventDefault();
            $('#remember').hide();
            $('#proceed').text("Use this time only");
            $('#proceed_and_remember').removeClass('hidden').show();
            $('#reset_info').removeClass('hidden').show();
            return false;
        },
        unselect: function (e) {
            //e.preventDefault();
            e.stopPropagation();
            var id = $(this).attr('rel');
            var idps = $.jStorage.get('pyff.discovery.idps', []);
            var idx = $.inArray(id, idps);
            if (idx != -1) {
                idps.splice(idx, 1);
                $.jStorage.set('pyff.discovery.idps', idps);
                $(this).parent().remove();
            }
            return false;
        },
        select: function(e) {
            //e.preventDefault();
            var lst = $.jStorage.get('pyff.discovery.idps', []);
            if (lst.length < 2) {
                return select_idp($(this).attr('data-href'));
            } else {
                return discovery_response($(this).attr('data-href'));
            }
            return false;
        },
        proceed: function(e) {
            //e.preventDefault();
            return discovery_response($(this).attr('data-href'));
        },
        proceed_and_remember: function(e) {
            //e.preventDefault();
            var entityID = $(this).attr('data-href');
            $.jStorage.set('pyff.discovery.idp',entityID);
            return discovery_response(entityID);
        }
    };

    $("img.fallback-icon").error(function(e) {
        $(this).attr('src','/static/img/1x1t.png').removeClass("img-thumbnail").hide();
    });

    var idp_template = Hogan.compile('<span class="cursor {{#proceed}}proceed{{/proceed}}{{^proceed}}select{{/proceed}} list-group-item" alt="{{title}}" data-href="{{entityID}}">' +
        '{{^sticky}}<button type="button" data-toggle="tooltip" data-placement="left" class="close unselect" rel="{{entityID}}">&times;</button>{{/sticky}}' +
        '<h4 class="list-group-item-heading">{{title}}</h4>' +
        '<p class="list-group-item-text">' +
        '{{#icon}}<img src="{{icon}}" class="fallback-icon hidden-xs idp-icon pull-right img-responsive img-thumbnail"/>{{/icon}}' +
        '{{#descr}}<div class="pull-left idp-description hidden-xs">{{descr}}</div>{{/descr}}</p>' +
        '<div class="clearfix"></div>' +
        '</span>');

    $.fn.dsQuickLinks = function(id) {
        this.each(function() {
            var outer = $(this);
            var uri = outer.attr('data-target');
            var div = $('<div>').addClass("list-group");
            outer.html(div);

            var miss = [];
            var seen = {};
            var lst = $.jStorage.get('pyff.discovery.idps',[]);
            if (lst.length > 0) {
                //console.log("adding previously used");
                for (var i = 0; i < lst.length; i++) {
                    console.log("adding ... " + lst[i]);
                    with_entity_id(lst[i], function (elt) { /* success */
                        //console.log(elt);
                        elt.sticky = false;
                        div.append(idp_template.render(elt));
                        seen[elt.entityID] = true
                    }, function (id) {  /* fail */
                        console.log("failing ... "+id);
                        miss.push(id);
                    });
                }
            } else {
                //console.log("adding suggestions...")
                $.getJSON(uri, function (data) {
                    $.each(data,function(pos,elt) {
                        //console.log(elt);
                        if (elt.entityID in seen) {
                        } else {
                            elt.sticky = true;
                            seen[elt.entityID] = true;
                            div.append(idp_template.render(elt));
                        }
                    });
                });
            }
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

    $.fn.dsRelyingParty = function(id, cb) {
        var o = $(this);
        $.ajax({
            url: '/metadata/'+ id +'.json',
            dataType: 'json',
            success: function(data) {
                for (var i = 0; i < data.length; i++) {
                    var entity = data[i];
                    $(o).filter("img.sp-icon").each(function() {
                        if (entity.icon) {
                            $(this).attr('src',entity.icon).addClass("img-responsive img-thumbnail")
                        } else {
                            $(this).hide();
                        }
                    });
                    $(o).filter(".sp-name").each(function() {
                        if (entity.title) {
                            $(this).append(entity.title)
                        }
                    });
                    $(o).filter(".sp-description").each(function() {
                        if (entity.descr) {
                            $(this).append(entity.descr);
                        }
                    });
                    $(o).filter("a.sp-privacy-statement-url").each(function() {
                        if (entity.psu) {
                            $(this).attr('href',entity.psu).append($('<em>').append($(this).attr('title')));
                        }
                    });
                    if (cb) {
                        cb(entity, i);
                    }
                }
            }
        });
    };
});
