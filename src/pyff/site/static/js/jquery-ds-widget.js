$.widget("pyff.discovery_client", {

    options:  {
        sp_entity_id: undefined,
        discovery_service_storage_url: undefined,
        discovery_service_search_url: undefined,
        discovery_service_list_url: undefined,
        before: undefined,
        after: undefined,
        render: undefined,
        fallback_icon: undefined
    },

    _create: function() {
        var obj = this;
        if (typeof obj.options['render'] !== 'function') {
            obj._template = Hogan.compile('<div data-href="{{entity_id}}" class="identityprovider list-group-item">' +
                '<button type="button" alt="{{ _(\"Remove from list\") }}" data-toggle="tooltip" data-placement="left" class="close">&times;</button>' +
                '<div class="media"><div class="d-flex mr-3"><div class="frame-round">' +
                '<div class="crop"><img{{#icon}} src="{{icon}}"{{/icon}} data-id={{entity_id}} class="pyff-idp-icon"/></div></div></div>' +
                '<div class="media-body"><h5 class="mt-0 mb-1">{{title}}</h5>{{#descr}}{{descr}}{{/descr}}</div>' +
                '</div></div>');

            obj.options['render'] = function(item) {
                return obj._template.render(item);
            }
        }
        if (typeof obj.options['fallback_icon'] != 'function') {
            obj.options['fallback_icon'] = $.noop
        }
        this._update();
    },

    _setOption: function( key, value ) {
        this.options[ key ] = value;
        this._update();
    },

    _render: function(item) {
        return this.options['render'](item);
    },

    _after: function(count) {
        if (typeof this.options['after'] == 'function') {
            return this.options['after'](count);
        } else {
            if (count == 0) {
                $(this.input_field_selector).parent().show();
            } else {
                $(this.input_field_selector).parent().hide();
            }
        }
    },

    _update: function() {
        this.discovery_service_storage_url = this.options['discovery_service_storage_url'] || this.element.attr('data-store');
        this.sp_entity_id = this.options['sp_entity_id'] || this.element.attr('data-href');
        this.discovery_service_search_url = this.options['discovery_service_search_url'] || this.element.attr('data-search');
        this.mdq_url = this.options['mdq_url'] || this.element.attr('data-mdq');
        this.input_field_selector = this.options['input_field_selector'] || this.element.attr('data-inputfieldselector') || 'input';
        var obj = this;
        this._ds = new DiscoveryService(this.mdq_url, this.discovery_service_storage_url, this.sp_entity_id);
        var top_element = this.element;

        $('img.pyff-idp-icon').
            bind('error', function () {
                $(this).unbind('error');
                obj.options['fallback_icon'](this);
            });

        $('body').on('mouseenter', 'div.identityprovider', function (e) {
            $(this).addClass("active");
        });
        $('body').on('mouseleave', 'div.identityprovider', function (e) {
           $(this).removeClass("active");
        });

        $('body').on('click', '.identityprovider', function (e) {
            var entity_id = $(this).closest('.identityprovider').attr('data-href');
            obj._ds.saml_discovery_response(entity_id);
        });

        $('body').on('click', '.close', function (e) {
            e.stopPropagation();
            var entity_element = $(this).closest('.identityprovider');
            var entity_id = entity_element.attr('data-href');
            if (entity_id) {
                obj._ds.remove(entity_id).then(function () {
                    entity_element.remove();
                });
            }
        });

        var saved_choices_element = $('<div>').addClass("list-group").attr('id','pyff-saved-choices');
        top_element.prepend(saved_choices_element);
        var search_list_element = $('<div>').addClass("list-group").attr('id','pyff-search-list');
        top_element.append(search_list_element);

        if (this.discovery_service_search_url && search_list_element) {
            var search_base, search_related, list_uri;
            search_base = $(top_element).attr('data-search');
            search_related = $(top_element).attr('data-related');
            $(this.input_field_selector).focus();
            $(search_list_element).btsListFilter(this.input_field_selector, {
                resetOnBlur: false,
                sourceData: function (text, callback) {
                    var remote = search_base + "?query=" + text + "&entity_filter={http://macedir.org/entity-category}http://pyff.io/category/discoverable";

                    if (search_related) {
                        remote = remote + "&related=" + search_related;
                    }
                    return $.getJSON(remote, callback);
                },
                sourceNode: function (data) {
                    return obj._render(data);
                },
                cancelNode: null
            });
        }

        this._ds.choices().then(function(entities) {
            if (typeof obj.options['before'] === 'function') {
                entities = obj.options['before'](entities);
            }
            return entities;
        }).then(function(entities) {
            var count = 0;
            entities.forEach(function (item) {
                var entity_element = obj._render(item.entity);
                saved_choices_element.append(entity_element);
                count++;
            });
            return count;
        }).then(function(count) {
            obj._after(count);
        })
    }

});