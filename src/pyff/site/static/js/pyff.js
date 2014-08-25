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

    _autoselect();

    function cancel_confirm(item) {
        $('#remember-selection-dlg').hide();
        $('.idpchooser').show();
    }

    function ds_select(item, confirm) {
        confirm &= $.jStorage.get('pyff.discovery.allow_confirm',true);
        if (confirm) {
            $('.idpchooser').hide();
            item.sticky = true;
            item.save = false;
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

    function contains_idp(idp,lst) {
        for (var i = 0; i < lst.length; i++) {
            var item = lst[i];
            if (item['entityID'] == idp['entityID']) {
                return true;
            }
        }
        return false;
    }

    function add_idp(item, save) {
        if (save) {
            var idps = $.jStorage.get('pyff.discovery.idps', []);
            //console.log(item);
            if (!contains_idp(item, idps)) {
                idps.unshift(item);
            }
            while (idps.length > 3) {
                idps.pop()
            }
            $.jStorage.set('pyff.discovery.idps', idps);
        }
        return ds_select(item, true);
    }

    function find_idp(id,lst) {
        for (var i = 0; i < lst.length; i++) {
            if (id == lst[i]['entityID']) {
                return i
            }
        }
        return -1
    }

    function select_idp(id, save) {
        $.ajax({
            datatype: 'json',
            url: '/metadata/' + id + ".json",
            success: function (data) {
                for (var i = 0; i < data.length; i++) {
                    //console.log("fetched: "+data[i]);
                    return add_idp(data[i], save);
                }
            }
        });
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
                       select_idp(entity.id, true);
                    }
                });
                $.each(options,function(key,val) {
                    seldiv.dsSelect(key,val);
                });
                $('body').on('click.ds', 'button.unselect', methods.unselect);
                $('body').on('click.ds', 'a.select', methods.select);
                $('body').on('click.ds', 'a.proceed', methods.proceed);
                $('body').on('click.ds', 'a.proceed_and_remember', methods.proceed_and_remember);
                $('body').on('click.ds', 'a.save_select', methods.save_select);
            });
            this.filter('select').each(function (opts) {
                var seldiv = $(this);
                seldiv.change(function(opt) {
                    //console.log(opt);
                    var sel = seldiv.find('option:selected')
                    select_idp(sel.attr('value'), true); // TODO - fix id in xsltjson xslt
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
                        seldiv.append($('<option>').attr('value','{sha1}'+CryptoJS.SHA1(elt.entityID)).append(elt.title));
                    })
                });
            });
        },
        unselect: function (e) {
            e.preventDefault();
            e.stopPropagation();
            var id = $(this).attr('rel');
            var idps = $.jStorage.get('pyff.discovery.idps', []);
            var idx = find_idp(id, idps);
            if (idx != -1) {
                idps.splice(idx, 1);
                $.jStorage.set('pyff.discovery.idps', idps);
                $(this).parent().remove();
            }
        },
        select: function(e) {
            e.preventDefault();
            return select_idp("{sha1}"+CryptoJS.SHA1($(this).attr('data-href')), false);
        },
        proceed: function(e) {
            e.preventDefault();
            return ds_select($(this).attr('data-href'), $(this).attr('alt'), false);
        },
        proceed_and_remember: function(e) {
            e.preventDefault();
            $.jStorage.set('pyff.discovery.idp',$(this).attr('data-href'));
            return ds_select($(this).attr('data-href'), $(this).attr('alt'), false);
        },
        save_select: function(e) {
            e.preventDefault();
            return select_idp("{sha1}"+CryptoJS.SHA1($(this).attr('data-href')), true);
        }
    };

    $("img.fallback-icon").error(function(e) {
        $(this).attr('src','1x1t.png').removeClass("img-thumbnail").hide();
    });

    var idp_template = Hogan.compile('<a class="{{#proceed}}proceed{{/proceed}}{{^proceed}}{{#save}}save_select{{/save}}{{^save}}select{{/save}}{{/proceed}} list-group-item" alt="{{title}}" data-href="{{entityID}}">' +
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
            var from_storage = 0;
            div.append(function() {
                var lst = $.jStorage.get('pyff.discovery.idps',[]);
                for (var i = 0; i < lst.length; i++) {
                    div.append(idp_template.render(lst[i]));
                    from_storage++;
                    seen[lst[i].entityID] = true
                }
            });

            if (from_storage == 0) {
                $.getJSON(uri, function (data) {
                    $.each(data,function(pos,elt) {
                        if (!(elt.entityID in seen)) {
                            elt.sticky = true;
                            elt.save = true;
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
