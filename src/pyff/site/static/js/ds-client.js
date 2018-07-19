(function() {

    const storage_key = "pyff_discovery_choices";
    const cache_time = 60 * 10 * 1000; // 10 minutes

    function DiscoveryService(mdq_url, storage_url, sp_entity_id, opts) {
       opts = opts || {};
       this.storage_url = storage_url;
       this.sp_entity_id = sp_entity_id;
       this.mdq_url = mdq_url;
    }

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
        return new CrossStorageClient(this.storage_url)
    };

    DiscoveryService.prototype.json_mdq_get = function(id) {
        return $.ajax({
            datatype: 'json',
            url: this.mdq_url + id + ".json"
        }).then(function (data) {
            if ($.isArray(data)) {
                data = data[0];
            }
            return data;
        },function (jqxHR, info, error) {
            console.log(info);
            return Promise.reject(error);
        });
    };

    DiscoveryService._now = function() {
        if (typeof Date.now === 'function') {
            return Date.now();
        }

        return new Date().getTime();
    };

    DiscoveryService.prototype.choices = function() {
        var obj = this;
        var storage = this.get_storage();
        return storage.onConnect().then(function () {
            console.log(storage_key);
            return storage.get(storage_key);
        }).then(function(data) {
            data = data || '[]';
            var lst = JSON.parse(data) || [];
            lst.sort(function (a, b) { // decending order - most commonly used stuff on top
                if (a.use_count < b.use_count) {
                    return 1;
                }
                if (a.use_count > b.use_count) {
                    return -1;
                }
                return 0;
            });

            while (lst.length > 3) {
                lst.pop();
            }

            lst.forEach(function(item) {
                var entity = item.entity;
                if (entity && entity.entityID && !entity.entity_id) {
                    entity.entity_id = entity.entityID;
                }
                if (entity && !entity.entity_icon && entity.icon) {
                    entity.entity_icon = entity.icon;
                }
            });

            return lst;
        });
    };

    DiscoveryService.prototype.each = function(callback) {
        var obj = this;
        var storage = this.get_storage();
        return storage.onConnect().then(function () {
            console.log(storage_key);
            return storage.get(storage_key);
        }).then(function(data) {
            var lst = JSON.parse(data || '[]') || [];
            lst.sort(function (a, b) { // decending order - most commonly used stuff on top
                if (a.use_count < b.use_count) {
                    return 1;
                }
                if (a.use_count > b.use_count) {
                    return -1;
                }
                return 0;
            });

            while (lst.length > 3) {
                lst.pop();
            }

            return Promise.all(lst.map(function(item,i) {
                var last_refresh = item.last_refresh || -1;
                if (last_refresh == -1 || last_refresh + cache_time < DiscoveryService._now()) {
                    var p = obj.json_mdq_get(item.entity.entity_id).then(function(entity) {
                        console.log(entity);
                        if (entity) {
                            item.entity = entity;
                            item.last_refresh = DiscoveryService._now();
                        }
                        return callback(item.entity);
                    });
                    return p;
                } else {
                    return new Promise(function (resolve, reject) { return callback(item.entity); });
                }
            })).then(function () {
                return storage.set(storage_key, JSON.stringify(lst));
            });
        })['catch'](function(err) { console.log(err); });
    };

    DiscoveryService.prototype.saml_discovery_response = function(entity_id) {
        var obj = this;
        return obj.add(entity_id).then(function() {
            console.log("returning discovery response...");
            var params = DiscoveryService._querystring;
            var qs;
            if (params['return']) {
                qs = params['return'].indexOf('?') === -1 ? '?' : '&';
                var returnIDParam = params['returnIDParam'];
                if (!returnIDParam) {
                    returnIDParam = "entityID";
                }
                console.log(params['return'] + qs + returnIDParam + '=' + entity_id);
                window.location = params['return'] + qs + returnIDParam + '=' + entity_id;
            }
        });
    };

    DiscoveryService._incr_use_count = function (entity_id, list) {
        for (var i = 0; i < list.length; i++) {
            if (list[i].entity.entity_id == entity_id || list[i].entity.entityID == entity_id) {
                var use_count = list[i].use_count;
                list[i].use_count += 1;
                return use_count;
            }
        }
        return -1;
    };

    DiscoveryService._sha1_id = function (s) {
        //var sha1 = new Hashes.SHA1();
        return "{sha1}"+hex_sha1(s);
    };

    DiscoveryService.prototype.add = function (id) {
        var storage = this.get_storage();
        var obj = this;
        return storage.onConnect().then(function () {
            return storage.get(storage_key);
        }).then(function (data) {
            var lst = JSON.parse(data || '[]') || [];
            console.log("found current list...")
            console.log(lst);
            var p;
            if (DiscoveryService._incr_use_count(id,lst) == -1) {
                p = obj.json_mdq_get(DiscoveryService._sha1_id(id)).then(function (entity) {
                    console.log("mdq found entity: ",entity);
                    lst.push({last_refresh: DiscoveryService._now(), use_count: 1, entity: entity});
                    return lst;
                });
            } else {
                p = Promise.resolve(lst);
            }
            console.log("final promise...");
            console.log(p);
            return p.then(function(lst) {
                console.log("setting...");
                console.log(lst);
                return storage.set(storage_key, JSON.stringify(lst));
            })
        });
    };

    DiscoveryService.prototype.remove = function (id) {
        var storage = this.get_storage();
        var obj = this;
        return storage.onConnect().then(function () {
            return storage.get(storage_key);
        }).then(function (data) {
            var lst = JSON.parse(data || '[]') || [];

            return lst.filter(function(item) {
                return item.entity.entity_id != id && item.entity.entityID != id;
            })
        }).then(function (lst) {
            return storage.set(storage_key, JSON.stringify(lst));
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