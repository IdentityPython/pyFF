/**
 * Created with PyCharm.
 * User: leifj
 * Date: 2/6/13
 * Time: 2:14 PM
 * To change this template use File | Settings | File Templates.
 */

(function( $ ) {
    if (!(window.console && console.log)) { (function() { var noop = function() {}; var methods = ['assert', 'clear', 'count', 'debug', 'dir', 'dirxml', 'error', 'exception', 'group', 'groupCollapsed', 'groupEnd', 'info', 'log', 'markTimeline', 'profile', 'profileEnd', 'markTimeline', 'table', 'time', 'timeEnd', 'timeStamp', 'trace', 'warn']; var length = methods.length; var console = window.console = {}; while (length--) { console[methods[length]] = noop; } }()); }

    function idpFormatResult(idp) {
        //console.log(idp);
        return idp['label']; //['label'];
    }

    function idpFormatSelection(idp) {
        //console.log(idp);
        return idp['value']; //['value'];
    }

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
                    idp.append($('<span>').addClass("idp-label").append(item['title']));
                    if (item['icon']) {
                        idp.append($('<img>').attr('src',item['icon']).addClass("fallback-icon idp-icon"));
                    }

                    var dismiss = $('<button>').attr('type',"button").addClass('close unselect').attr('rel',item['entityID']).append("&times;");
                    idp.append(dismiss);
                    outer.append(idp);
                    $(this).append(outer);
                }
            }));
        });
    };
    $.fn.dsSelect = function() {
        this.each(function() {
            var $this = $(this);
            $this.select2({
                placeholder: "Search for a login provider...",
                ajax: {
                    url: '${search}',
                    data: function(term,page) {
                        return {
                            query: term,
                            page_limit: 10,
                            page: page,
                            paged: true,
                            entity_filter: '{http://pyff-project.org/role}idp'
                        };
                    },
                    results: function(data,page) {
                        var more = (page*10) < data['total'];
                        return {results: data['entities'], more: more}
                    }
                },
                formatResult: idpFormatResult,
                formatSelection: idpFormatSelection,
                dropdownCssClass: 'bigdrop',
                width: 'resolve'
            });
        });
    };
    $.fn.dsRelyingParty = function() {
        var o = $(this);
        $.ajax({
            url: '/metadata/${sp}.json',
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