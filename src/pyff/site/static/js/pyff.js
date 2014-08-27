/**
 * Created with PyCharm.
 * User: leifj
 * Date: 2/6/13
 * Time: 2:14 PM
 * To change this template use File | Settings | File Templates.
 */

(function( $ ) {
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
                lst[i] = lst[i].id
            }
        }
        $.jStorage.set('pyff.discovery.idps',lst);
    }

    _convert_local_store_fmt();
    _autoselect();

    function cancel_confirm() {
        $('#remember-selection-dlg').hide();
        $('.idpchooser').show();
    }

    function ds_confirm_select(item, save) {
        var allow_confirm = $.jStorage.get('pyff.discovery.allow_confirm',true);
        if (allow_confirm) {
            $('.idpchooser').hide();
            item.sticky = true;
            item.save = true;
            item.proceed = true;
            $("#confirm").html(idp_template.render(item));
            $('#proceed').attr("data-href", item['entityID']);
            $('#proceed_and_remember').attr("data-href", item['entityID']);
            if ($('#never-remember-selection-again').is(':checked')) {
                $.jStorage.set('pyff.discovery.allow_confirm', false);
            }
            $('#remember-selection-dlg').removeClass('hidden').show();
        } else {
            return discovery_response(item['entityID']);
        }
    }

    function discovery_response(entityID) {
        var idps = $.jStorage.get('pyff.discovery.idps', []);
        console.log(idps);
        console.log(entityID);
        if ($.inArray(entityID, idps) != -1) {

        } else {
            idps.unshift(entityID);
        }
        console.log(idps);
        while (idps.length > 3) {
            idps.pop()
        }
        $.jStorage.set('pyff.discovery.idps', idps);

        var params;
        params = $.deparam.querystring();
        var qs;
        //console.log(entityID);
        qs = params['return'].indexOf('?') === -1 ? '?' : '&';
        var returnIDParam = params['returnIDParam'];
        if (!returnIDParam) {
            returnIDParam = "entityID";
        }
        window.location = params['return'] + qs + returnIDParam + '=' + entityID;
        return false;
    }

    function with_entity_id(entityID, func) {
        console.log("with entity id "+entityID);
        with_id(sha1_id(entityID), func);
    }

    function with_id(id, func) {
        console.log("with_id "+id);
        var cached = $.jStorage.get(id);
        if (cached) {
            console.log("cached...");
            console.log(cached);
            func(cached);
        } else {
            console.log('GET /metadata/' + id + ".json");
            $.ajax({
                datatype: 'json',
                url: '/metadata/' + id + ".json"
            }).done(function (data) {
                if ($.isArray(data)) {
                    for (var i = 0; i < data.length; i++) {
                        console.log("fetched: ")
                        console.log(data[i]);
                        $.jStorage.set(id,data[i],{TTL: 300000});
                        func(data[i]);
                    }
                } else {
                    console.log("got: ")
                    console.log(data);
                    $.jStorage.set(id,data,{TTL: 300000});
                    func(data);
                }
            });
        }
    }

    function select_idp(id) {
        with_id(id, ds_confirm_select);
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
                var remote = uri+"?query=%QUERY&entity_filter={http://pyff-project.org/role}idp";
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
                        console.log("selected "+entity.id);
                        select_idp(entity.id);
                    }
                });
                $.each(options,function(key,val) {
                    seldiv.dsSelect(key,val);
                });
                $('body').on('click.ds', 'button.unselect', methods.unselect);
                $('body').on('click.ds', 'a.select', methods.select);
                $('body').on('click.ds', 'a.proceed', methods.proceed);
                $('body').on('click.ds', 'a.proceed_and_remember', methods.proceed_and_remember);
                $('body').on('click.ds', 'a.cancel', cancel_confirm)
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
        refresh: function() {
            this.filter('select').each(function() {
                var seldiv = $(this);
                seldiv.html($('<option>').attr('value','').append($('<em>').append(seldiv.attr('title'))))
                $.getJSON('/role/idp.json',function (data) {
                    $.each($(data).sort(cmp_title),function(pos,elt) {
                        //console.log(elt);
                        seldiv.append($('<option>').attr('value',sha1_id(entityID)).append(elt.title));
                    })
                });
            });
        },
        unselect: function (e) {
            e.preventDefault();
            e.stopPropagation();
            var id = $(this).attr('rel');
            var idps = $.jStorage.get('pyff.discovery.idps', []);
            var idx = $.inArray(id, idps);
            if (idx != -1) {
                idps.splice(idx, 1);
                $.jStorage.set('pyff.discovery.idps', idps);
                $(this).parent().remove();
            }
        },
        select: function(e) {
            e.preventDefault();
            return select_idp(sha1_id($(this).attr('data-href')));
        },
        proceed: function(e) {
            e.preventDefault();
            return discovery_response($(this).attr('data-href'));
        },
        proceed_and_remember: function(e) {
            e.preventDefault();
            var entityID = $(this).attr('data-href')
            $.jStorage.set('pyff.discovery.idp',entityID);
            return discovery_response(entityID);
        }
    };

    $("img.fallback-icon").error(function(e) {
        $(this).attr('src','1x1t.png').removeClass("img-thumbnail").hide();
    });

    var idp_template = Hogan.compile('<a class="{{#proceed}}proceed{{/proceed}}{{^proceed}}select{{/proceed}} list-group-item" alt="{{title}}" data-href="{{entityID}}">' +
        '{{^sticky}}<button type="button" class="close unselect" rel="{{entityID}}">&times;</button>{{/sticky}}' +
        '<h4 class="list-group-item-heading">{{title}}</h4>' +
        '<p class="list-group-item-text">' +
        '{{#icon}}<img src="{{icon}}" class="fallback-icon hidden-xs idp-icon pull-right img-responsive img-thumbnail"/>{{/icon}}' +
        '{{#descr}}<div class="pull-left idp-description hidden-xs">{{descr}}</div>{{/descr}}</p>' +
        '<div class="clearfix"></div>' +
        '</a>');

    $.fn.dsQuickLinks = function(id) {
        this.each(function() {
            var outer = $(this);
            var uri = outer.attr('data-target');
            var div = $('<div>').addClass("list-group");
            outer.html(div);

            var seen = {};
            var lst = $.jStorage.get('pyff.discovery.idps',[]);
            if (lst.length > 0) {
                console.log("adding previously used");
                for (var i = 0; i < lst.length; i++) {
                    console.log("adding ... " + lst[i]);
                    with_entity_id(lst[i], function (elt) {
                        console.log("blaha");
                        console.log(elt);
                        elt.sticky = false;
                        div.append(idp_template.render(elt));
                        seen[elt.entityID] = true
                    });
                }
            } else {
                console.log("adding suggestions...")
                $.getJSON(uri, function (data) {
                    $.each(data,function(pos,elt) {
                        console.log(elt);
                        if (elt.entityID in seen) {
                            // nothing
                        } else {
                            elt.sticky = true;
                            seen[elt.entityID] = true
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

    $.fn.dsRelyingParty = function(id) {
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
                }
            }
        });
    };
})( jQuery );
