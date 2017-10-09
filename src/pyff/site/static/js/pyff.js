

$(document).ready(function() {
    // send the user directly to the pre-selected idp if that setting exists

    var idp_template;
    idp_template = Hogan.compile('<div class="cursor {{#proceed}}proceed{{/proceed}}{{^proceed}}select{{/proceed}} list-group-item" alt="{{title}}" data-href="{{entityID}}">' +
        '{{^sticky}}<button type="button" data-toggle="tooltip" data-placement="left" class="close unselect" rel="{{entityID}}">&times;</button>{{/sticky}}' +
        '<h4 class="list-group-item-heading">{{title}}</h4>' +
        '<p class="list-group-item-text">' +
        '{{#icon}}<img src="{{icon}}" class="idp-icon pull-right img-responsive img-thumbnail" onerror="this.style.display=\'none\';"/>{{/icon}}' +
        '{{#descr}}<div class="pull-left idp-description hidden-xs">{{descr}}</div>{{/descr}}</p>' +
        '<div class="clearfix"></div>' +
        '</div>');

    function _autoselect() {
        var use_idp;
        use_idp = $.jStorage.get('pyff.discovery.idp');
        if (use_idp) {
            with_entity_id(use_idp, function (elt) { // found entity - autoselect
                if (typeof elt.hidden === 'undefined' || elt.hidden.toLowerCase() === "false") {
                    discovery_response(elt.entityID);
                }
            }, function () { // failing - lets remove the selection and have the user re-select
                $.jStorage.remove('pyff.discovery.idp');
            });
        }
    }

    function sha1_id(entityID) {
        var sha1 = new Hashes.SHA1;
        return "{sha1}"+sha1.hex(entityID);
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

    //_convert_local_store_fmt();
    _autoselect();

    function _clone(o) {
        return jQuery.extend({},o);
    }

    function cancel_confirm() {
        window.location.reload();
    }

    function ds_confirm_select(item) {
        $('#idpchooser').hide();
        item.sticky = true;
        item.save = true;
        item.proceed = true;
        $('.confirm').html(idp_template.render(item));
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
        with_id(sha1_id(entityID), func, fail_func);
    }

    var cache_time = 60 * 10 * 1000; /* 10 minutes in milliseconds */

    function with_id(id, func, fail_func) {
        var cached = $.jStorage.get(id);
        if (cached) {
            if ($.jStorage.getTTL(id) <= 0 || $.jStorage.getTTL(id) > cache_time) {
                $.jStorage.setTTL(id, cache_time);
            }
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
            }).fail(function (status) {
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

    var methods;
    methods = {
        fetch: function(uri, cb, async) {
            $('#searchindicator').removeClass('fa-search').addClass("fa-spinner fa-spin");
            $('#searchinput').addClass('disabled');
            if (async) {
                return oboe(uri).node({ '!.*': cb }).done(function () {
                    $('#searchindicator').removeClass("fa-spinner").removeClass("fa-spin").addClass('fa-search');
                    $('#searchinput').removeClass('disabled');
                }).fail(function() {
                    $('#searchindicator').removeClass("fa-spinner").removeClass("fa-spin").addClass('fa-search');
                    $('#searchinput').removeClass('disabled');
                });
            } else {
                return $.getJSON(uri, function (json) {
                    cb(json);
                }).done(function () {
                    $('#searchindicator').removeClass("fa-spinner").removeClass("fa-spin").addClass('fa-search');
                    $('#searchinput').removeClass('disabled');
                }).fail(function () {
                    $('#searchindicator').removeClass("fa-spinner").removeClass("fa-spin").addClass('fa-search');
                    $('#searchinput').removeClass('disabled');
                });
            }
        },
        init: function (options) {
            var search_base, search_related, list_uri;
            search_base = $('#searchinput').attr('data-target');
            search_related = $('#searchinput').attr('data-related');
            $('#searchinput').focus();

            var list = $('#searchlist').btsListFilter('#searchinput', {
                resetOnBlur: false,
                sourceData: function (text, callback) {
                    var remote = search_base + "?query=" + text + "&entity_filter={http://macedir.org/entity-category}http://pyff.io/category/discoverable";

                    if (search_related) {
                        remote = remote + "&related=" + search_related;
                    }

                    return methods.fetch(remote, callback, false);
                },
                sourceNode: function (data) {
                    data.sticky = true;
                    return idp_template.render(data);
                },
                cancelNode: null
            });
        },
        show: function (e) {
            var search_base, search_related, list_uri;
            search_base = $('#searchinput').attr('data-target');
            search_related = $('#searchinput').attr('data-related');
            var remote = search_base + "?query=&entity_filter={http://macedir.org/entity-category}http://pyff.io/category/discoverable";
            if (search_related) {
                remote = remote + "&related=" + search_related;
            }
            $('#idpchooser > form[role="form"]').removeClass('hidden');
            methods.fetch(remote, function (elt) {
                elt.sticky = true;
                //console.log(elt);
                $('#searchlist').append(idp_template.render(elt));
            }, true);
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
            e.stopPropagation();
            var id = $(this).attr('rel');
            var idps = $.jStorage.get('pyff.discovery.idps', []);
            var idx = $.inArray(id, idps);
            if (idx != -1) {
                idps.splice(idx, 1);
                $.jStorage.set('pyff.discovery.idps', idps);
                $(this).parent().remove();
            }
            if ($.jStorage.get('pyff.discovery.idps',[]).length == 0) {
                methods.show();
            }
            return false;
        },
        select: function (e) {
            var elt = $(this).closest('.select');
            var lst = $.jStorage.get('pyff.discovery.idps', []);
            if (lst.length < 2) {
                return select_idp(elt.attr('data-href'));
            } else {
                return discovery_response(elt.attr('data-href'));
            }
            return false;
        },
        proceed: function (e) {
            return discovery_response($(this).attr('data-href'));
        },
        proceed_and_remember: function (e) {
            var entityID = $(this).attr('data-href');
            $.jStorage.set('pyff.discovery.idp', entityID);
            return discovery_response(entityID);
        }
    };

    $('body').on('vclick.ds', 'button.unselect', methods.unselect);
    $('body').on('vclick.ds', '.select', methods.select);
    $('body').on('vclick.ds', '.proceed', methods.proceed);
    $('body').on('vclick.ds', '.proceed', methods.proceed);
    $('body').on('vclick.ds', '.remember', methods.remember);
    $('body').on('vclick.ds', '.proceed_and_remember', methods.proceed_and_remember);
    $('body').on('vclick.ds', '.cancel', cancel_confirm);
    $('body').on('mouseenter', 'div.list-group-item', function (e) {
       $(this).addClass("active");
    });
    $('body').on('mouseleave', 'div.list-group-item', function (e) {
       $(this).removeClass("active");
    });

    $("img.fallback").error(function(e) {
        $(this).attr('src','/static/icons/1x1t.png').removeClass("img-thumbnail").hide();
    });

    $.fn.dsQuickLinks = function(id, done_cb) {
        this.each(function() {
            var outer = $(this);
            var uri = outer.attr('data-target');
            var div = $('<div>').addClass("list-group");
            outer.html(div);

            var lst = $.jStorage.get('pyff.discovery.idps',[]);
            if (lst.length > 0) {
                var i = lst.length;
                while (i--) {
                    with_entity_id(lst[i], function (elt) { /* success */
                        if (typeof elt.hidden === 'undefined' || elt.hidden.toLowerCase() === "false") {
                            elt.sticky = false;
                            div.prepend(idp_template.render(elt));
                        }
                    }, function (id) {  /* fail */
                        lst.splice(i, 1);
                        $.jStorage.set('pyff.discovery.idps',lst);
                    });
                }
                done_cb(lst.length,"foo");
            } else {
                var seen_count = 0;
                var seen = {};
                //console.log(uri);
                oboe(uri).node('!.*', function (elt) {
                    if (elt.entityID in seen) {
                    } else {
                        elt.sticky = true;
                        seen[elt.entityID] = true;
                        seen_count++;
                        div.append(idp_template.render(elt));
                    }
                }).done(function () {
                    done_cb(seen_count,"bar");
                }).fail(function () {
                    done_cb(seen_count,"baz");
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

});
