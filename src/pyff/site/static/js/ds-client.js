(function() {

    var storage_key = "pyff_discovery_choices";
    var cache_time = 60 * 10 * 1000; // 10 minutes

    // polyfill Object.values()
    if (!Object.values) Object.values = function (object) {
        return Object.keys(object).map(function(key) { return object[key] });
    };

    function DiscoveryService(mdq_url, storage_url, opts) {
       opts = opts || {};
       this.mdq_url = mdq_url;
       this.storage_url = storage_url;
    }

    // a shim layer to regular localstore which can be used to speed up access if called from the same origin
    DiscoveryService.LocalStoreShim = function (opts) { };

    DiscoveryService.LocalStoreShim.prototype.onConnect = function() {
        return Promise.resolve(this);
    };

    DiscoveryService.LocalStoreShim.prototype.set = function(key, value) {
        var storage = window.localStorage;
        storage.setItem(key, value);
        return Promise.resolve(this);
    };

    DiscoveryService.LocalStoreShim.prototype.get = function(key) {
        var storage = window.localStorage;
        return Promise.resolve(storage.getItem(key));
    };

    DiscoveryService._querystring = (function(paramsArray) {
        var params = {};

        for (var i = 0; i < paramsArray.length; ++i)
        {
            var param = paramsArray[i]
                .split('=', 2);

            if (param.length !== 2)
                continue;

            params[param[0]] = decodeURIComponent(param[1].replace(/\+/g, " "));
        }

        return params;
    })(window.location.search.substr(1).split('&'));

    DiscoveryService.prototype.get_storage = function() {
        if (this.storage_url == 'local://') {
            return new DiscoveryService.LocalStoreShim()
        } else {
            return new CrossStorageClient(this.storage_url)
        }
    };

    DiscoveryService.prototype.json_mdq_get = function(id) {
        var opts = {method: 'GET', headers: {}};
        return fetch(this.mdq_url + id + ".json",opts).then(function (response) {
            var contentType = response.headers.get("content-type");
            if(contentType && contentType.includes("application/json")) {
              return response.json();
            }
            throw new TypeError("MDQ didn't provide a JSON response");
        }).then(function(data) {
            if (Object.prototype.toString.call(data) === "[object Array]") {
                data = data[0];
            }
            return data;
        }).catch(function(error) {
            console.log(error);
            Promise.reject(error);
        });
    };

    DiscoveryService._now = function() {
        if (typeof Date.now === 'function') {
            return Date.now();
        }

        return new Date().getTime();
    };

    DiscoveryService.prototype.with_items = function(callback) {
        var obj = this;
        var storage = this.get_storage();
        return storage.onConnect().then(function () {
            console.log("pyFF ds-client: Listing discovery choices");
            return storage.get(storage_key);
        }).then(function(data) {
            data = data || '[]';
            var lst;
            try {
                lst = JSON.parse(data) || [];
            } catch (error) {
                console.log(error);
                lst = [];
            }

            var clean = {};
            for (var i = 0; i < lst.length; i++) {
                if (lst[i].entity && (lst[i].entity.entity_id || lst[i].entity.entityID) && lst[i].entity.title) {
                    var entity = lst[i].entity;
                    if (entity && entity.entityID && !entity.entity_id) {
                       entity.entity_id = entity.entityID;
                    }
                    if (entity && !entity.entity_icon && entity.icon) {
                       entity.entity_icon = entity.icon;
                    }
                    clean[entity.entity_id] = lst[i];
                }
            }

            lst = Object.values(clean);

            while (lst.length > 3) {
                lst.pop();
            }

            lst.sort(function (a, b) { // most commonly used last in list
                if (a.last_use < b.last_use) {
                    return -1;
                }
                if (a.last_use > b.last_use) {
                    return 1;
                }
                return 0;
            });

            return Promise.all(lst.map(function(item,i) {
                var now = DiscoveryService._now();
                var last_refresh = item.last_refresh || -1;
                if (last_refresh == -1 || last_refresh + cache_time < now) {
                    var id = DiscoveryService._sha1_id(item.entity['entity_id'] || item.entity['entityID']);
                    return obj.json_mdq_get(id).then(function(entity) {
                        if (entity) {
                            item.entity = entity;
                            item.last_refresh = now;
                        }
                        return item;
                    });
                } else {
                    return Promise.resolve(item);
                }
            })).then(callback);
        }).then(function(items) { storage.set(storage_key, JSON.stringify(items))});
    };

    DiscoveryService.prototype.saml_discovery_response = function(entity_id) {
        var params = DiscoveryService._querystring;
        return this.do_saml_discovery_response(entity_id, params).then(function (url) {
            window.location = url;
        });
    };

    DiscoveryService.prototype.pin = function(entity_id) {
        return this.do_saml_discovery_response(entity_id, {});
    };

    DiscoveryService.prototype.do_saml_discovery_response = function(entity_id, params) {
        var obj = this;
        return obj.with_items(function(items) {
            if (DiscoveryService._touch(entity_id, items) == -1) {
                return obj.json_mdq_get(DiscoveryService._sha1_id(entity_id)).then(function (entity) {
                    console.log("mdq found entity: ",entity);
                    var now = DiscoveryService._now();
                    items.push({last_refresh: now, last_use: now, use_count: 1, entity: entity});
                    return items;
                });
            } else {
                return Promise.resolve(items);
            }
        }).then(function() {
            var qs;
            if (params['return']) {
                console.log("returning discovery response...");
                qs = params['return'].indexOf('?') === -1 ? '?' : '&';
                var returnIDParam = params['returnIDParam'];
                if (!returnIDParam) {
                    returnIDParam = "entityID";
                }
                var response = params['return'];
                if (entity_id) {
                    response += qs + returnIDParam + '=' + entity_id;
                }
                console.log(response);
                return response;
            }
        });
    };

    DiscoveryService._touch = function (entity_id, list) {
        for (var i = 0; i < list.length; i++) {
            var item = list[i];
            if (item.entity.entity_id == entity_id || item.entity.entityID == entity_id) {
                var now = DiscoveryService._now();
                var use_count = item.use_count;
                item.use_count += 1;
                item.last_use = now;
                return use_count;
            }
        }
        return -1;
    };

    DiscoveryService._sha1_id = function (s) {
        return "{sha1}"+hex_sha1(s);
    };

    DiscoveryService.prototype.remove = function (id) {
        return this.with_items(function (items) {
           return items.filter(function(item) {
                return item.entity.entity_id != id && item.entity.entityID != id;
           })
        });
    };

    // exposes DiscoveryService
    (function(window, undefined) {
        var freeExports = false;
        if (typeof exports === 'object') {
          freeExports = exports;
          if (exports && typeof global === 'object' && global && global === global.global) {
            window = global;
          }
        }

        if (typeof define === 'function' && typeof define.amd === 'object' && define.amd) {
            // define as an anonymous module, so, through path mapping, it can be aliased
            define(function() {
                return DiscoveryService;
            });
        } else if (freeExports) {
        // in Node.js or RingoJS v0.8.0+
            if (typeof module === 'object' && module && module.exports === freeExports) {
                module.exports = DiscoveryService;
            }
            // in Narwhal or RingoJS v0.7.0-
            else {
                freeExports.DiscoveryService = DiscoveryService;
            }
        } else {
            // in a browser or Rhino
            window.DiscoveryService = DiscoveryService;
        }
    }(this));

}());
