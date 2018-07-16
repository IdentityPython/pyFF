jQuery(function ($) {
    $.widget("pyff.discovery_client", {

        options: {
            sp_entity_id: undefined,
            discovery_service_storage_url: undefined,
            discovery_service_search_url: undefined,
            discovery_service_list_url: undefined,
            before: undefined,
            after: undefined,
            render: undefined,
            render_search_result: undefined,
            render_saved_choice: undefined,
            fallback_icon: undefined,
            search_result_selector: '#ds-search-list',
            saved_choices_selector: '#ds-saved-choices',
            selection_selector: '.identityprovider'
        },

        _create: function () {
            var obj = this;
            if (typeof obj.options['render'] !== 'function') {
                obj._template_with_icon = Hogan.compile('<div data-href="{{entity_id}}" class="identityprovider list-group-item">' +
                    '{{^sticky}}<button type="button" alt="{{ _(\"Remove from list\") }}" data-toggle="tooltip" data-placement="left" class="close">&times;</button>{{/sticky}}' +
                    '<div class="media"><div class="d-flex mr-3"><div class="frame-round">' +
                    '<div class="crop"><img{{#entity_icon}} src="{{entity_icon}}"{{/entity_icon}} data-id={{entity_id}} class="pyff-idp-icon"/></div></div></div>' +
                    '<div class="media-body"><h5 class="mt-0 mb-1">{{title}}</h5>{{#descr}}{{descr}}{{/descr}}</div>' +
                    '</div></div>');
                obj._template_no_icon = Hogan.compile('<div data-href="{{entity_id}}" class="identityprovider list-group-item">' +
                    '{{^sticky}}<button type="button" alt="{{ _(\"Remove from list\") }}" data-toggle="tooltip" data-placement="left" class="close">&times;</button>{{/sticky}}' +
                    '<div class="media"><div class="d-flex mr-3"><div class="frame-round" style="visibility: hidden;">' +
                    '<div class="crop"><img{{#entity_icon}} src="{{entity_icon}}"{{/entity_icon}} data-id={{entity_id}} class="pyff-idp-icon"/></div></div></div>' +
                    '<div class="media-body"><h5 class="mt-0 mb-1">{{title}}</h5>{{#descr}}{{descr}}{{/descr}}</div>' +
                    '</div></div>');

                obj.options['render'] = function (item) {
                    item.selection_class = obj.selection_class;
                    if ('entity_icon' in item) {
                        return obj._template_with_icon.render(item);
                    } else {
                        return obj._template_no_icon.render(item);
                    }
                }
            }
            if (!$.isFunction(obj.options['render_search_result'])) {
                obj.options['render_search_result'] = obj.options['render'];
            }
            if (!$.isFunction(obj.options['render_saved_choice'])) {
                obj.options['render_saved_choice'] = obj.options['render'];
            }
            if (!$.isFunction(obj.options['fallback_icon'])) {
                obj.options['fallback_icon'] = $.noop;
            }
            if (!$.isFunction(obj.options['after'])) {
                obj.options['after'] = $.noop;
            }
            if (!$.isFunction(obj.options['before'])) {
                obj.options['before'] = function(x) { return x; }
            }
            obj._update();
        },

        _setOption: function (key, value) {
            this.options[key] = value;
            this._update();
        },

        _after: function (count) {
            var saved_choices_element = $(this.options['saved_choices_selector']);
            if (this.discovery_service_search_url) {
                var obj = this;
                var search_result_element = $(obj.options['search_result_selector']);
                var search_base, search_related, list_uri;
                var counter = 0;
                search_base = obj.element.attr('data-search');
                search_related = obj.element.attr('data-related');
                $(obj.input_field_selector).focus();
                search_result_element.btsListFilter(obj.input_field_selector, {
                    resetOnBlur: false,
                    casesensitive: false,
                    itemEl: '.identityprovider',
                    itemFilter: function (item, val) { return true; },
                    emptyNode: obj.options['no_results'],
                    getValue: function(that) {
                        var v = that.val();
                        var i = v.indexOf('@');
                        return i > -1 ? v.substring(i+1,v.length) : v;
                    },
                    sourceData: function (text, callback) {
                        var remote = search_base + "?query=" + text + "&entity_filter={http://macedir.org/entity-category}http://pyff.io/category/discoverable";

                        if (search_related) {
                            remote = remote + "&related=" + search_related;
                        }

                        counter = 0;
                        return $.getJSON(remote, callback);
                    },
                    sourceNode: function (data) {
                        data.sticky = true;
                        counter += 1;
                        data.counter = counter;
                        return obj.options['render_search_result'](data);
                    },
                    cancelNode: null
                });
            }
            this.options['after'](count, saved_choices_element);
        },

        _update: function () {
            var obj = this;
            obj.discovery_service_storage_url = obj.options['discovery_service_storage_url'] || obj.element.attr('data-store');
            obj.sp_entity_id = obj.options['sp_entity_id'] || obj.element.attr('data-href');
            obj.discovery_service_search_url = obj.options['discovery_service_search_url'] || obj.element.attr('data-search');
            obj.mdq_url = obj.options['mdq_url'] || obj.element.attr('data-mdq');
            obj.input_field_selector = obj.options['input_field_selector'] || obj.element.attr('data-inputfieldselector') || 'input';
            obj.selection_selector = obj.options['selection_selector'];
            obj._ds = new DiscoveryService(obj.mdq_url, obj.discovery_service_storage_url, obj.sp_entity_id);
            obj._count = 0;
            var top_element = obj.element;

            $('img.pyff-idp-icon').bind('error', function () {
                $(this).unbind('error');
                obj.options['fallback_icon'](this);
            });

            $('body').on('mouseenter', obj.selection_selector, function (e) {
                $(this).addClass("active");
            });
            $('body').on('mouseleave', obj.selection_selector, function (e) {
                $(this).removeClass("active");
            });

            $('body').on('click', obj.selection_selector, function (e) {
                var entity_id = $(this).closest(obj.selection_selector).attr('data-href');
                console.log(entity_id);
                return obj._ds.saml_discovery_response(entity_id);
            });

            $(obj.input_field_selector).closest('form').submit(function(e) {
                e.preventDefault();
            });

            $('body').on('click', '.close', function (e) {
                e.stopPropagation();
                var entity_element = $(this).closest(obj.selection_selector);
                var entity_id = entity_element.attr('data-href');
                if (entity_id) {
                    obj._ds.remove(entity_id).then(function () {
                        entity_element.remove();
                    }).then(function() {
                        obj._count -= 1;
                        obj._after(obj._count)
                    });
                }
            });

            obj._ds.choices().then(function (entities) {
                return obj.options['before'](entities);
            }).then(function (entities) {
                obj._count = 0;
                var saved_choices_element = $(obj.options['saved_choices_selector']);
                entities.forEach(function (item) {
                    var entity_element = obj.options['render_saved_choice'](item.entity);
                    saved_choices_element.prepend(entity_element);
                    obj._count++;
                });
                return obj._count;
            }).then(function (count) {
                obj._after(count);
            })
        }

    })
})
