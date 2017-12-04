$.widget("pyff.discovery_client", {

    options:  {
        sp_entity_id: undefined,
        discovery_service_storage_url: undefined,
        discovery_service_search_url: undefined,
        discovery_service_list_url: undefined
    },

    _create: function() {
        this._entity_template = Hogan.compile('<div data-href="{{entity_id}}" class="identityprovider list-group-item">' +
            '<button type="button" data-toggle="tooltip" data-placement="left" class="close">&times;</button>'+
            '<div class="media">'+
            '<div class="media-body"><h5 class="mt-0 mb-1">{{title}}</h5>{{#descr}}{{descr}}{{/descr}}</div>'+
            '{{#icon}}<div class="d-flex ml-3"><img src="{{icon}}" class="pyff-idp-icon img-responsive rounded-circle"/></div>{{/icon}}</div></div>');
        this._entity_template2 = Hogan.compile('<div class="identityprovider list-group-item" alt="{{title}}" data-href="{{entity_id}}">' +
        '{{^sticky}}<button type="button" data-toggle="tooltip" data-placement="left" class="close" rel="{{entity_id}}">&times;</button>{{/sticky}}' +
        '<h4 class="list-group-item-heading">{{title}}</h4>' +
        '<p class="list-group-item-text">' +
        '{{#icon}}<div class="d-inline-block mh-25 mw-25 pull-right"><img src="{{icon}}" class="pyff-idp-icon img-responsive rounded" onerror="console.log(event); this.style.display=\'none\';"/>{{/icon}}</div>' +
        '{{#descr}}<div class="d-inline-block pyff-idp-description mw-50 small hidden-xs">{{descr}}</div>{{/descr}}</p>' +
        '<div class="clearfix"></div>' +
        '</div>');
        this._update();
    },

    _setOption: function( key, value ) {
        this.options[ key ] = value;
        this._update();
    },

    _update: function() {
        var discovery_service_storage_url = this.options['discovery_service_storage_url'] || this.element.attr('data-store');
        var sp_entity_id = this.options['sp_entity_id'] || this.element.attr('data-href');
        var discovery_service_search_url = this.options['discovery_service_search_url'] || this.element.attr('data-search');
        var mdq_url = this.options['mdq_url'] || this.element.attr('data-mdq');
        var input_field_selector = this.options['input_field_selector'] || this.element.attr('data-inputfieldselector') || 'input';
        var obj = this;
        this._ds = new DiscoveryService(mdq_url, discovery_service_storage_url, sp_entity_id);
        var top_element = this.element;

        $('body').on('mouseenter', 'div.identityprovider', function (e) {
            $(this).addClass("active");
        });
        $('body').on('mouseleave', 'div.identityprovider', function (e) {
           $(this).removeClass("active");
        });

        $('body').on('click', '.identityprovider', function (e) {
            console.log(e);
            console.log(this);
            var entity_id = $(this).closest('.identityprovider').attr('data-href');
            obj._ds.saml_discovery_response(entity_id);
        });

        $('body').on('click', '.close', function (e) {
            e.stopPropagation();
            var entity_element = $(this).closest('.identityprovider');
            var entity_id = entity_element.attr('data-href');
            console.log("removing... "+entity_id);
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
        var count = 0;
        this._ds.choices().then(function(entities) {
            return entities.map(function (item) {
                var entity_element = obj._entity_template.render(item.entity);
                saved_choices_element.append(entity_element);
                count++;
            });
        });
        console.log(count);
        if (discovery_service_search_url && search_list_element) {
            var search_base, search_related, list_uri;
            search_base = $(top_element).attr('data-search');
            search_related = $(top_element).attr('data-related');
            $(input_field_selector).focus();
            $(search_list_element).btsListFilter(input_field_selector, {
                resetOnBlur: false,
                sourceData: function (text, callback) {
                    var remote = search_base + "?query=" + text + "&entity_filter={http://macedir.org/entity-category}http://pyff.io/category/discoverable";

                    if (search_related) {
                        remote = remote + "&related=" + search_related;
                    }
                    return $.getJSON(remote,callback);
                },
                sourceNode: function (data) {
                    console.log(data);
                    return obj._entity_template.render(data);
                },
                cancelNode: null
            });
        }
    }

});