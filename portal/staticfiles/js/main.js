const routes = [
  { path: '/dashboard', component: httpVueLoader('/static/js/dashboard.vue') },
  { path: '/assets', component: httpVueLoader('/static/js/assets.vue') },
  { path: '/network', component: httpVueLoader('/static/js/network.vue') },
  { path: '/user', component: httpVueLoader('/static/js/user.vue') },
  { path: '/', redirect: '/dashboard'}
]

const router = new VueRouter({
  routes
})

const app = new Vue({
  router,
  data: function() {
    return {
      assets: [],
      nested_data: [],
      user_data: {},
      vulns: [],
      stats: null,
      doms: null,
      asset_doms: [],
      current_doms: [],
      net_data: {"graph": [],
                 "links": [],
                 "nodes": [],
                 "directed": false,
                 "multigraph": false
                 },
      is_scanned: false,
      net_map_loaded: false,
      net_map_force: null,
      net_svg_width: 900,
      net_svg_height: 400,
      scan_history: {'labels':[],
                     'datasets':[]
                     },
      current_sort:'name',
      current_sortdir:'asc',
      search_query: '',
      current_poc: '',
      flushChart: false,
      asset_columns: [{key:'name', name:'Name'},
                       {key:'domain', name:'Domain'},
                       {key:'current_score', name:'Current Score'},
                       {key:'created_date', name:'Created Date'},
                       {key:'schedule', name:'Schedule'}],
      dom_columns: [{key:'fqdn', name: 'FQDN'},
                    {key:'ip', name:'IPv4'},
                    {key:'total_score', name:'Score'},
                    {key:'confidence', name:'Confidence'},
                    {key:'country', name:'Country'},
                    {key:'found_date', name:'Found Date'},
                    {key:'plugin', name:'Plugin'}],
      add_asset_name: '',
      add_asset_domain: '',
      edit_asset_id: '',
      edit_asset_name: '',
      updateTasksTimer: '',
      objSelected: {},
      objRefresh: false,
      map_loading: true,
      table_loading: true,
      history_loading: true,
      world_loading: true,
      assets_loading: true,
      stats_loading: true,
      top_loading: true,
      tasks: [],
      active_tasks: {},
      active_plugins: {},
      active_progress: [],
      form_error: '',
      scan_updating: false,
      nameState: null,
      scanSettingsState: null,
      createdScan: "",
      scanAssetId: "",
      scanAssetName: "",
      userFields: {'id': "ID",
      'username': "User Name",
      'first_name': "First Name",
      'last_name': "Last Name",
      'email': "Email",
      'token': "API Token",
      'created_date': "Created Date",
      'last_login': "Last Login",
      'is_superuser': "Administrator"},
      scanSettingsData: {'name': 'default',
                        'active': true,
                        'inscope': true,
                        'recursive': true,
                        'repeat': false,
                        'repeat_freq': 'DAILY',
                        'notify': false,
                        'top_ports':'50'
                        },
      submittedNames: [],
    }
  },
  methods: {
        retrieveToken: function() {
            axios.get('/pulsar/api/v1/user/').then(response => {
                this.user_data = response.data;
            })
        },
        isEmpty: function(obj) {
                for(var key in obj) {
                    if(obj.hasOwnProperty(key))
                        return false;
                }
                return true;
            },
        getCDoms: async function(){
            return await axios.get('/pulsar/api/v1/doms/active/?format=json')
        },
        truncate: function truncateString(str, num) {
            if (str.length > num) {
                return str.slice(0, num) + "..."
            } else {
                return str
            }
        },
        getCountryStats: function(){
            var doms = app.current_doms;
            var countries = {};
            doms.forEach(function(dom){
                if (countries.hasOwnProperty(dom.country)){
                    countries[dom.country] = countries[dom.country] + 1
                } else {
                    countries[dom.country] = 1
                }
            });
            return countries
        },
        renderNetworkMap: function (){
            var w = document.getElementById("net-map-canvas").clientWidth;
            var h = document.getElementById("net-map-canvas").clientHeight;

            var keyc = true, keys = true, keyt = true, keyr = true, keyx = true, keyd = true, keyl = true, keym = true, keyh = true, key1 = true, key2 = true, key3 = true, key0 = true

            var focus_node = null, highlight_node = null;

            var text_center = false;
            var outline = false;

            var min_score = 0;
            var max_score = 10;

            var color = d3.scale.linear()
              .domain([min_score, (min_score+max_score)/2, max_score])
              .range(["lime", "yellow", "red"]);

            var highlight_color = "#fff";
            var highlight_trans = 0.8;

            var size = d3.scale.pow().exponent(1)
              .domain([1,100])
              .range([8,24]);

            var force = d3.layout.force()
              .linkDistance(180)
              .charge(-2200)
              .size([w,h])
              .stop();
            app.net_map_force = force;

            var default_node_color = "#eee";
            var default_link_color = "var(--base)";
            var nominal_base_node_size = 8;
            var nominal_text_size = 18;
            var max_text_size = 24;
            var nominal_stroke = 1.5;
            var max_stroke = 4.5;
            var max_base_node_size = 36;
            var min_zoom = 0.1;
            var max_zoom = 2;
            d3.select("svg[id=net-map-svg]").remove();
            var svg = d3.select("div[id=net-map-canvas]").append("svg").attr("id", "net-map-svg");
            var zoom = d3.behavior.zoom().scaleExtent([min_zoom,max_zoom])
            var g = svg.append("g");
            svg.style("cursor","move");

            graph = app.net_data;

            var linkedByIndex = {};
                graph.links.forEach(function(d) {
                linkedByIndex[d.source + "," + d.target] = true;
                });

                function isConnected(a, b) {
                    return linkedByIndex[a.index + "," + b.index] || linkedByIndex[b.index + "," + a.index] || a.index == b.index;
                }

                function hasConnections(a) {
                    for (var property in linkedByIndex) {
                            s = property.split(",");
                            if ((s[0] == a.index || s[1] == a.index) && linkedByIndex[property]) 					return true;
                    }
                return false;
                }

              force
                .nodes(graph.nodes)
                .friction(0.5)
                .links(graph.links)
                .start();

              var link = g.selectAll(".link")
                .data(graph.links)
                .enter().append("line")
                .attr("class", "link")
                .style("stroke-width",nominal_stroke)
                .style("stroke", function(d) {
                if (isNumber(d.score) && d.score>=0.0) return color(d.score);
                else return default_link_color; })

               safety = 0;


              var node = g.selectAll(".node")
                .data(graph.nodes)
                .enter().append("g")
                .attr("class", "node")

                .call(force.drag)


                node.on("dblclick.zoom", function(d) { d3.event.stopPropagation();
                var dcx = (document.getElementById("net-map-canvas").clientWidth/2-d.x*zoom.scale());
                var dcy = (document.getElementById("net-map-canvas").clientHeight/2-d.y*zoom.scale());
                zoom.translate([dcx,dcy]);
                 g.attr("transform", "translate("+ dcx + "," + dcy  + ")scale(" + zoom.scale() + ")");

                });

                var tocolor = "fill";
                var towhite = "stroke";
                if (outline) {
                    tocolor = "stroke"
                    towhite = "fill"
                }
              var circle = node.append("path")
                  .attr("d", d3.svg.symbol()
                    .size(function(d) { return Math.PI*Math.pow(size(d.size)||nominal_base_node_size,2); })
                    .type(function(d) { return d.type; }))

                .style(tocolor, function(d) {
                if (isNumber(d.score) && d.score>0.0) return color(d.score);
                else return default_node_color; })
                .style("stroke-width", nominal_stroke);


              var text = g.selectAll(".text")
                .data(graph.nodes)
                .enter().append("text")
                .attr("dy", ".35em")
                .style("font-size", nominal_text_size + "px").style(tocolor, "white").style("opacity", "0.9")

                if (text_center)
                 text.text(function(d) { return d.id; })
                .style("text-anchor", "middle");
                else
                text.attr("dx", function(d) {return (size(d.size)||nominal_base_node_size);})
                .text(function(d) { return '\u2002'+d.id; });

                node.on("mouseover", function(d) {
                set_highlight(d);
                })
              .on("mousedown", function(d) { d3.event.stopPropagation();
                focus_node = d;
                set_focus(d)
                if (highlight_node === null) set_highlight(d)

            }	).on("mouseout", function(d) {
                    exit_highlight();

            }	);

                    d3.select(window).on("mouseup",
                    function() {
                    if (focus_node!==null)
                    {
                        focus_node = null;
                        if (highlight_trans<1)
                        {

                    circle.style("opacity", 1);
                  text.style("opacity", 1).style(tocolor, "white");
                  link.style("opacity", 1);
                }
                    }

                if (highlight_node === null) exit_highlight();
                    });

            function exit_highlight()
            {
                    highlight_node = null;
                if (focus_node===null)
                {
                    svg.style("cursor","move");
                    if (highlight_color!="white")
                {
                  circle.style(towhite, "var(--base)");
                  text.style("font-weight", "normal").style("opacity", "1.0").style(tocolor, "white");
                  link.style("stroke", function(o) {return (isNumber(o.score) && o.score>=0.0)?color(o.score):default_link_color});
             }

                }
            }

            function set_focus(d)
            {
            if (highlight_trans<1)  {
                circle.style("opacity", function(o) {
                            return isConnected(d, o) ? 1 : highlight_trans;
                        }).style(towhite, "var(--base)");

                        text.style("opacity", function(o) {
                            return isConnected(d, o) ? 1 : highlight_trans;
                        });

                        link.style("opacity", function(o) {
                            return o.source.index == d.index || o.target.index == d.index ? 1 : highlight_trans;
                        });
                }
            }


            function set_highlight(d)
            {
                svg.style("cursor","pointer");
                if (focus_node!==null) d = focus_node;
                highlight_node = d;

                if (highlight_color!="white")
                {
                      circle.style(towhite, function(o) {
                            return isConnected(d, o) ? highlight_color : "var(--base)";});
                        text.style("font-weight", function(o) {
                            return isConnected(d, o) ? "bold" : "normal";}).style(tocolor, "white");
                        link.style("stroke", function(o) {
                          return o.source.index == d.index || o.target.index == d.index ? highlight_color : ((isNumber(o.score) && o.score>=0)?color(o.score):default_link_color);

                        });
                }
            }


              zoom.on("zoom", function() {

                var stroke = nominal_stroke;
                if (nominal_stroke*zoom.scale()>max_stroke) stroke = max_stroke/zoom.scale();
                link.style("stroke-width",stroke);
                circle.style("stroke-width",stroke);

                var base_radius = nominal_base_node_size;
                if (nominal_base_node_size*zoom.scale()>max_base_node_size) base_radius = max_base_node_size/zoom.scale();
                    circle.attr("d", d3.svg.symbol()
                    .size(function(d) { return Math.PI*Math.pow(size(d.size)*base_radius/nominal_base_node_size||base_radius,2); })
                    .type(function(d) { return d.type; }))

                if (!text_center) text.attr("dx", function(d) { return (size(d.size)*base_radius/nominal_base_node_size||base_radius); });

                var text_size = nominal_text_size;
                if (nominal_text_size*zoom.scale()>max_text_size) text_size = max_text_size/zoom.scale();
                text.style("font-size",text_size + "px").style(tocolor, "white");

                g.attr("transform", "translate(" + d3.event.translate + ")scale(" + d3.event.scale + ")");
                });

              svg.call(zoom);

              resize();
              //window.focus();
              d3.select(window).on("resize", resize).on("keydown", keydown);
              force.on("tick", () => {
                node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
                text.attr("transform", d => "translate(" + d.x + "," + d.y + ")");

                link
                  .attr("x1", d => d.source.x)
                  .attr("y1", d => d.source.y)
                  .attr("x2", d => d.target.x)
                  .attr("y2", d => d.target.y);

                node
                  .attr("cx", d => d.x)
                  .attr("cy", d => d.y);
                });


              function resize() {
                var width = document.getElementById("net-map-canvas").clientWidth, height = document.getElementById("net-map-canvas").clientHeight;
                svg.attr("width", width).attr("height", height);

                force.size([force.size()[0]+(width-w)/zoom.scale(),force.size()[1]+(height-h)/zoom.scale()]).resume();
                w = width;
                h = height;
                }

                function keydown() {
                if (d3.event.keyCode==32) {  force.stop();}
                else if (d3.event.keyCode>=48 && d3.event.keyCode<=90 && !d3.event.ctrlKey && !d3.event.altKey && !d3.event.metaKey)
                {
              switch (String.fromCharCode(d3.event.keyCode)) {
                case "C": keyc = !keyc; break;
                case "S": keys = !keys; break;
                case "T": keyt = !keyt; break;
                case "R": keyr = !keyr; break;
                case "X": keyx = !keyx; break;
                case "D": keyd = !keyd; break;
                case "L": keyl = !keyl; break;
                case "M": keym = !keym; break;
                case "H": keyh = !keyh; break;
                case "1": key1 = !key1; break;
                case "2": key2 = !key2; break;
                case "3": key3 = !key3; break;
                case "0": key0 = !key0; break;
              }

              link.style("display", function(d) {
                            var flag  = vis_by_type(d.source.type)&&vis_by_type(d.target.type)&&vis_by_node_score(d.source.score)&&vis_by_node_score(d.target.score)&&vis_by_link_score(d.score);
                            linkedByIndex[d.source.index + "," + d.target.index] = flag;
                          return flag?"inline":"none";});
              node.style("display", function(d) {
                            return (key0||hasConnections(d))&&vis_by_type(d.type)&&vis_by_node_score(d.score)?"inline":"none";});
              text.style("display", function(d) {
                            return (key0||hasConnections(d))&&vis_by_type(d.type)&&vis_by_node_score(d.score)?"inline":"none";}).style(tocolor, "white");

                            if (highlight_node !== null)
                            {
                                if ((key0||hasConnections(highlight_node))&&vis_by_type(highlight_node.type)&&vis_by_node_score(highlight_node.score)) {
                                if (focus_node!==null) set_focus(focus_node);
                                set_highlight(highlight_node);
                                }
                                else {exit_highlight();}
                            }

            }
            }

            function vis_by_type(type)
            {
                switch (type) {
                  case "circle": return keyc;
                  case "square": return keys;
                  case "triangle-up": return keyt;
                  case "diamond": return keyr;
                  case "cross": return keyx;
                  case "triangle-down": return keyd;
                  default: return true;
            }
            }
            function vis_by_node_score(score)
            {
                if (isNumber(score))
                {
                if (score>=0.666) return keyh;
                else if (score>=0.333) return keym;
                else if (score>=0) return keyl;
                }
                return true;
            }

            function vis_by_link_score(score)
            {
                if (isNumber(score))
                {
                if (score>=0.666) return key3;
                else if (score>=0.333) return key2;
                else if (score>=0) return key1;
            }
                return true;
            }

            function isNumber(n) {
              return !isNaN(parseFloat(n)) && isFinite(n);
            }
          app.map_loading = false;
          },
        renderNetworkMapFull: function (){
            var w = document.getElementById("net-map-fullscreen").clientWidth;
            var h = document.getElementById("net-map-fullscreen").offsetParent.clientHeight;

            var keyc = true, keys = true, keyt = true, keyr = true, keyx = true, keyd = true, keyl = true, keym = true, keyh = true, key1 = true, key2 = true, key3 = true, key0 = true

            var focus_node = null, highlight_node = null;

            var text_center = false;
            var outline = false;

            var min_score = 0;
            var max_score = 10;

            var color = d3.scale.linear()
              .domain([min_score, (min_score+max_score)/2, max_score])
              .range(["lime", "yellow", "red"]);

            var highlight_color = "#fff";
            var highlight_trans = 0.8;

            var size = d3.scale.pow().exponent(1)
              .domain([1,100])
              .range([8,24]);

            var force = d3.layout.force()
              .linkDistance(180)
              .charge(-2200)
              .size([w,h])
              .stop();
            app.net_map_force = force;

            var default_node_color = "#eee";
            var default_link_color = "var(--base)";
            var nominal_base_node_size = 8;
            var nominal_text_size = 18;
            var max_text_size = 24;
            var nominal_stroke = 1.5;
            var max_stroke = 4.5;
            var max_base_node_size = 36;
            var min_zoom = 0.1;
            var max_zoom = 2;
            d3.select("svg[id=net-map-svg]").remove();
            var svg = d3.select("div[id=net-map-fullscreen]").append("svg").attr("id", "net-map-svg");
            var zoom = d3.behavior.zoom().scaleExtent([min_zoom,max_zoom])
            var g = svg.append("g");
            svg.style("cursor","move");

            graph = app.net_data;

            var linkedByIndex = {};
                graph.links.forEach(function(d) {
                linkedByIndex[d.source + "," + d.target] = true;
                });

                function isConnected(a, b) {
                    return linkedByIndex[a.index + "," + b.index] || linkedByIndex[b.index + "," + a.index] || a.index == b.index;
                }

                function hasConnections(a) {
                    for (var property in linkedByIndex) {
                            s = property.split(",");
                            if ((s[0] == a.index || s[1] == a.index) && linkedByIndex[property]) 					return true;
                    }
                return false;
                }

              force
                .nodes(graph.nodes)
                .friction(0.5)
                .links(graph.links)
                .start();

              var link = g.selectAll(".link")
                .data(graph.links)
                .enter().append("line")
                .attr("class", "link")
                .style("stroke-width",nominal_stroke)
                .style(towhite, "var(--base)")
                .style("stroke", function(d) {
                if (isNumber(d.score) && d.score>=0.0) return color(d.score);
                else return default_link_color; })

               safety = 0;


              var node = g.selectAll(".node")
                .data(graph.nodes)
                .enter().append("g")
                .attr("class", "node")

                .call(force.drag)


                node.on("dblclick.zoom", function(d) { d3.event.stopPropagation();
                var dcx = (document.getElementById("net-map-canvas").clientWidth/2-d.x*zoom.scale());
                var dcy = (document.getElementById("net-map-canvas").clientHeight/2-d.y*zoom.scale());
                zoom.translate([dcx,dcy]);
                 g.attr("transform", "translate("+ dcx + "," + dcy  + ")scale(" + zoom.scale() + ")");

                });

                var tocolor = "fill";
                var towhite = "stroke";
                if (outline) {
                    tocolor = "stroke"
                    towhite = "fill"
                }
              var circle = node.append("path")
                  .attr("d", d3.svg.symbol()
                    .size(function(d) { return Math.PI*Math.pow(size(d.size)||nominal_base_node_size,2); })
                    .type(function(d) { return d.type; }))

                .style(tocolor, function(d) {
                if (isNumber(d.score) && d.score>0.0) return color(d.score);
                else return default_node_color; })
                .style("stroke-width", nominal_stroke);


              var text = g.selectAll(".text")
                .data(graph.nodes)
                .enter().append("text")
                .attr("dy", ".35em")
                .style("font-size", nominal_text_size + "px").style(tocolor, "white").style("opacity", "0.9")

                if (text_center)
                 text.text(function(d) { return d.id; })
                .style("text-anchor", "middle");
                else
                text.attr("dx", function(d) {return (size(d.size)||nominal_base_node_size);})
                .text(function(d) { return '\u2002'+d.id; });

                node.on("mouseover", function(d) {
                set_highlight(d);
                })
              .on("mousedown", function(d) { d3.event.stopPropagation();
                focus_node = d;
                set_focus(d)
                if (highlight_node === null) set_highlight(d)

            }	).on("mouseout", function(d) {
                    exit_highlight();

            }	);

                    d3.select(window).on("mouseup",
                    function() {
                    if (focus_node!==null)
                    {
                        focus_node = null;
                        if (highlight_trans<1)
                        {

                    circle.style("opacity", 1).style(towhite, "var(--base)");
                  text.style("opacity", 1).style(tocolor, "white");
                  link.style("opacity", 1);
                }
                    }

                if (highlight_node === null) exit_highlight();
                    });

            function exit_highlight()
            {
                    highlight_node = null;
                if (focus_node===null)
                {
                    svg.style("cursor","move");
                    if (highlight_color!="white")
                {
                  circle.style(towhite, "var(--base)");
                  text.style("font-weight", "normal").style("opacity", "0.9").style(tocolor, "white");
                  link.style("stroke", function(o) {return (isNumber(o.score) && o.score>=0.0)?color(o.score):default_link_color});
             }

                }
            }

            function set_focus(d)
            {
            if (highlight_trans<1)  {
                circle.style("opacity", function(o) {
                            return isConnected(d, o) ? 1 : highlight_trans;
                        }).style(towhite, "var(--base)");

                        text.style("opacity", function(o) {
                            return isConnected(d, o) ? 1 : highlight_trans;
                        });

                        link.style("opacity", function(o) {
                            return o.source.index == d.index || o.target.index == d.index ? 1 : highlight_trans;
                        });
                }
            }


            function set_highlight(d)
            {
                svg.style("cursor","pointer");
                if (focus_node!==null) d = focus_node;
                highlight_node = d;

                if (highlight_color!="white")
                {
                      circle.style(towhite, function(o) {
                            return isConnected(d, o) ? highlight_color : "var(--base)";});
                        text.style("font-weight", function(o) {
                            return isConnected(d, o) ? "bold" : "normal";}).style(tocolor, "white");
                        link.style("stroke", function(o) {
                          return o.source.index == d.index || o.target.index == d.index ? highlight_color : ((isNumber(o.score) && o.score>=0)?color(o.score):default_link_color);

                        });
                }
            }


              zoom.on("zoom", function() {

                var stroke = nominal_stroke;
                if (nominal_stroke*zoom.scale()>max_stroke) stroke = max_stroke/zoom.scale();
                link.style("stroke-width",stroke);
                circle.style("stroke-width",stroke);

                var base_radius = nominal_base_node_size;
                if (nominal_base_node_size*zoom.scale()>max_base_node_size) base_radius = max_base_node_size/zoom.scale();
                    circle.attr("d", d3.svg.symbol()
                    .size(function(d) { return Math.PI*Math.pow(size(d.size)*base_radius/nominal_base_node_size||base_radius,2); })
                    .type(function(d) { return d.type; }))

                if (!text_center) text.attr("dx", function(d) { return (size(d.size)*base_radius/nominal_base_node_size||base_radius); });

                var text_size = nominal_text_size;
                if (nominal_text_size*zoom.scale()>max_text_size) text_size = max_text_size/zoom.scale();
                text.style("font-size",text_size + "px").style(tocolor, "white");

                g.attr("transform", "translate(" + d3.event.translate + ")scale(" + d3.event.scale + ")");
                });

              svg.call(zoom);

              resize();
              d3.select(window).on("resize", resize).on("keydown", keydown);
              force.on("tick", () => {
                node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
                text.attr("transform", d => "translate(" + d.x + "," + d.y + ")");

                link
                  .attr("x1", d => d.source.x)
                  .attr("y1", d => d.source.y)
                  .attr("x2", d => d.target.x)
                  .attr("y2", d => d.target.y);

                node
                  .attr("cx", d => d.x)
                  .attr("cy", d => d.y);
                });


              function resize() {
                var width = document.getElementById("net-map-fullscreen").clientWidth;
                var height = document.getElementById("net-map-fullscreen").offsetParent.clientHeight;
                svg.attr("width", width).attr("height", height);

                force.size([force.size()[0]+(width-w)/zoom.scale(),force.size()[1]+(height-h)/zoom.scale()]).resume();
                w = width;
                h = height;
                }

                function keydown() {
                if (d3.event.keyCode==32) {  force.stop();}
                else if (d3.event.keyCode>=48 && d3.event.keyCode<=90 && !d3.event.ctrlKey && !d3.event.altKey && !d3.event.metaKey)
                {
              switch (String.fromCharCode(d3.event.keyCode)) {
                case "C": keyc = !keyc; break;
                case "S": keys = !keys; break;
                case "T": keyt = !keyt; break;
                case "R": keyr = !keyr; break;
                case "X": keyx = !keyx; break;
                case "D": keyd = !keyd; break;
                case "L": keyl = !keyl; break;
                case "M": keym = !keym; break;
                case "H": keyh = !keyh; break;
                case "1": key1 = !key1; break;
                case "2": key2 = !key2; break;
                case "3": key3 = !key3; break;
                case "0": key0 = !key0; break;
              }

              link.style("display", function(d) {
                            var flag  = vis_by_type(d.source.type)&&vis_by_type(d.target.type)&&vis_by_node_score(d.source.score)&&vis_by_node_score(d.target.score)&&vis_by_link_score(d.score);
                            linkedByIndex[d.source.index + "," + d.target.index] = flag;
                          return flag?"inline":"none";}).style(towhite, "var(--base)");
              node.style("display", function(d) {
                            return (key0||hasConnections(d))&&vis_by_type(d.type)&&vis_by_node_score(d.score)?"inline":"none";}).style(towhite, "#393e46");
              text.style("display", function(d) {
                            return (key0||hasConnections(d))&&vis_by_type(d.type)&&vis_by_node_score(d.score)?"inline":"none";}).style(tocolor, "white");

                            if (highlight_node !== null)
                            {
                                if ((key0||hasConnections(highlight_node))&&vis_by_type(highlight_node.type)&&vis_by_node_score(highlight_node.score)) {
                                if (focus_node!==null) set_focus(focus_node);
                                set_highlight(highlight_node);
                                }
                                else {exit_highlight();}
                            }

            }
            }

            function vis_by_type(type)
            {
                switch (type) {
                  case "circle": return keyc;
                  case "square": return keys;
                  case "triangle-up": return keyt;
                  case "diamond": return keyr;
                  case "cross": return keyx;
                  case "triangle-down": return keyd;
                  default: return true;
            }
            }
            function vis_by_node_score(score)
            {
                if (isNumber(score))
                {
                if (score>=0.666) return keyh;
                else if (score>=0.333) return keym;
                else if (score>=0) return keyl;
                }
                return true;
            }

            function vis_by_link_score(score)
            {
                if (isNumber(score))
                {
                if (score>=0.666) return key3;
                else if (score>=0.333) return key2;
                else if (score>=0) return key1;
            }
                return true;
            }

            function isNumber(n) {
              return !isNaN(parseFloat(n)) && isFinite(n);
            }

          },
        updateNetData: function(){
                d3.select("svg[id=net-map-svg]").remove();
                 app.net_data = {"graph": [],
                     "links": [],
                     "nodes": [],
                     "directed": false,
                     "multigraph": false
                     };
                var false_positives = [];
                app.current_doms.forEach( function(dom){
                    if (dom.false_positive === true){
                        false_positives.push(dom.fqdn)
                    }
                });
                app.current_doms.forEach( function(dom){
                    false_positives.forEach(function(fp){
                        if (dom.reference.includes(fp)){
                            ref_arr = dom.reference.split(";");
                            ref_arr.splice(ref_arr.indexOf(fp), 1);
                            dom.reference = ref_arr.join(";")
                            app.current_doms[app.current_doms.indexOf(dom)] = dom;
                        }
                    });
                    if (dom.false_positive === false) {
                        dom_id = dom.id.split('/')[7];
                        asset_id = dom.asset.split('/')[7];
                        asset = app.assets.find(x => x.id === asset_id);
                        domscore = dom.total_score
                        if (dom.ips.length === 0 && dom.total_score === 0.0){
                            domscore = 'none'
                        }
                        dom_obj = {
                            "size": (dom.confidence*2),
                            "score": domscore,
                            "id": dom.fqdn,
                            "type": "circle",
                            "weight": 1,
                            "ref": dom_id
                            }

                        var new_dom = true;
                        app.net_data.nodes.forEach(function (n){
                            if (n.id === dom.fqdn){
                                dom_index = app.net_data.nodes.indexOf(n);
                                Vue.set(app.net_data.nodes, dom_index, dom_obj);
                                new_dom = false
                            }
                        });

                        if (new_dom ) {
                            app.net_data.nodes.push(dom_obj);
                            dom_index = app.net_data.nodes.length-1;
                        }

                         asset_obj = {
                            "size": 50,
                            "score": asset.current_score,
                            "weight": 1,
                            "id": asset.name,
                            "type": "square",
                            "ref": asset_id
                            }

                        var new_asset = true;
                        app.net_data.nodes.forEach(function (n){
                            if (n.ref === asset_id){
                                new_asset = false
                            }
                        })
                        if (new_asset) {
                            app.net_data.nodes.push(asset_obj);
                            asset_index = app.net_data.nodes.length-1;
                        } else {
                            asset_index = app.net_data.nodes.indexOf(
                                app.net_data.nodes.find(x => x.ref === asset_id)
                            );
                            Vue.set(app.net_data.nodes, asset_index, asset_obj);
                        }
                        if (dom.reference.length  === 0) {
                            app.makeLink(asset_index, dom_index);
                        }

                        if (dom.ips.length > 0){
                            dom.ips.forEach(function (ip){
                                dom_id = ip.domain.split('/')[7];
                                ip_id = ip.id.split('/')[7];
                                asset_id = ip.asset.split('/')[7];

                                ip_obj = {
                                    "size": 1,
                                    "score": ip.score,
                                    "id": ip.ip,
                                    "type": "triangle-up",
                                    "weight": 1,
                                    "ref": ip_id
                                    }
                                var new_ip = true;
                                app.net_data.nodes.forEach(function (n){
                                    if (n.id === ip.ip ){
                                        ip_index = app.net_data.nodes.indexOf(n);
                                        if (app.net_data.nodes[ip_index].score < ip.score){
                                            Vue.set(app.net_data.nodes, ip_index, ip_obj);
                                        }
                                        new_ip = false
                                    }
                                });

                                if (new_ip) {
                                    app.net_data.nodes.push(ip_obj);
                                    ip_index = app.net_data.nodes.length-1;
                                }

                                app.makeLink(dom_index, ip_index)

                            })
                        }

                        if (dom.ips.length > 0){
                            dom.ips.forEach(function (ip){
                                dom_id = ip.domain.split('/')[7];
                                ip_id = ip.id.split('/')[7];
                                asset_id = ip.asset.split('/')[7];
                                asn_name = "AS"+ip.asn+" ("+ip.desc+")"

                                asn_obj = {
                                    "size": 1,
                                    "score": 'none',
                                    "id": asn_name,
                                    "type": "diamond",
                                    "weight": 1,
                                    "ref": ip_id
                                    }
                                var new_asn = true;
                                app.net_data.nodes.forEach(function (n){
                                    if (n.id.split(' ')[0] === asn_name.split(' ')[0] ){
                                        asn_index = app.net_data.nodes.indexOf(n);
                                        new_asn = false
                                    }
                                    if (n.id === ip.ip){
                                        ip_index = app.net_data.nodes.indexOf(n);
                                    }
                                });

                                if (new_asn) {
                                    app.net_data.nodes.push(asn_obj);
                                    asn_index = app.net_data.nodes.length-1;
                                }

                                app.makeLink(ip_index, asn_index)

                            })
                        }
                    }
                });
                app.current_doms.some( function(dom){
                       if (dom.reference.length > 0 && dom.false_positive === false) {
                                var dom_a = '';
                                if (dom.fqdn.length > 0){
                                    dom_a = dom.fqdn;
                                } else {
                                    dom_a = dom.ip;
                                }
                                ref_arr = dom.reference.split(';');
                                ref = ref_arr[ref_arr.length-1];
                                if (app.net_data.nodes.find(x => x.id === dom_a).type === 'circle') {
                                    dom_index = app.net_data.nodes.indexOf(app.net_data.nodes.find(x => x.id === dom_a));
                                    ref_index = app.net_data.nodes.indexOf(app.net_data.nodes.find(x => x.id === ref));

                                    if (ref_index > -1) {
                                        app.makeLink(ref_index, dom_index);
                                    }
                                }
                       }

                    });
                app.net_map_loaded = true;
          },
        loadNetworkData: function() {
            axios.get('/pulsar/api/v1/assets/?format=json&ordering=-modified_date')
              .then(response => {
                this.assets = app.cleanData(response.data);
                }).then(response => {
                axios.get('/pulsar/api/v1/doms/active/?format=json')
                        .then(response => {
                            this.current_doms = response.data;
                        }).then(() => {
                            this.updateNetData();
                        })
                }).then(() => {
                    axios.get('/pulsar/api/v1/assets/detailed/?format=json&ordering=-modified_date')
                                  .then(response => {
                                    app.nested_data = response.data;
                                  }).then(() => {
                                    this.renderNetworkMap();
                                  });
                })
        },
        falsePositive: function(id, asset, value){

            axios.patch(id, {"false_positive": value}, {headers:this.csrfToken()})
                .then(response => {
                    this.objSelected[Object.keys(this.objSelected)[0]] = response.data;
                    axios.get(asset.split('?')[0]+'recalculate/')
                }).then(() => {
                    this.flushChart = !this.flushChart;
                    this.loadNetworkData();
                });
        },
        csrfToken: function(){
          var token = "";
          cookiearr = document.cookie.split(';');
          cookiearr.forEach(function (arrayItem) {
                if (arrayItem.includes('csrftoken')){
                    token = arrayItem.split('=')[1]
                }
            });
          return {'X-CSRFTOKEN':token}
          },
        sort: function(s) {
            if(s === this.current_sort) {
              this.current_sortdir = this.current_sortdir==='asc'?'desc':'asc';
            }
            this.current_sort = s;
          },
        isActive: function(){
            if (app.assets.length > 0){
                return true
            } else {
                return false
            }
          },
        sortedAssets:function(x) {
            return x.sort((a,b) => {
              let modifier = 1;
              if(this.current_sortdir === 'desc') modifier = -1;
              if(a[this.current_sort] < b[this.current_sort]) return -1 * modifier;
              if(a[this.current_sort] > b[this.current_sort]) return 1 * modifier;
              return 0;
            });
          },
        renderDomainsChart: function() {
            var doms = [];
            var scores = [];
            this.current_doms.forEach(function (arrayItem) {
                if (!doms.includes(arrayItem.fqdn) && doms.length < 5){
                    var snum = arrayItem.total_score;
                    if (snum > 0 && arrayItem.false_positive === false){
                        scores.push(snum.toFixed(2) * arrayItem.confidence);
                        doms.push(arrayItem.fqdn);
                    }
                }
            });
            new Chart(document.getElementById("domainsChart"), {
            type: 'horizontalBar',
            data: {
              labels: doms,
              datasets: [
                {
                  label: "Score",
                  backgroundColor: ["#FF073A", "#D021EB", "#5E29FF", "#266BEB", "#1CF3FF","#E83CAC", "#36FF74"],
                  data: scores
                }
              ]
            },
            options: {
                        tooltips: {
                            callbacks: {
                                labelTextColor: function(tooltipItem, chart) {
                                    return '#ffffffaa';
                                    }
                                }
                            },
                        legend: { display: false },
                        scales: {
                            xAxes:[{
                                ticks: {beginAtZero: true, max: 10.0, fontColor: "#ffffff66"},
                                gridLines: {
                                  display: false,
                                }
                            }],
                            yAxes:[{
                                    ticks: {fontColor: "#ffffff66"},
                                    gridLines: {
                                      display: false,
                                    }
                                }]
                            }
              }
            });
          },
        renderStatisticsChart: function() {
            if (app.stats.Assets === 0) {
                var stats = ["empty database"]
                var values = [1]
            } else {
                var stats = Object.keys(app.stats);
                var values = Object.values(app.stats)
            }
            new Chart(document.getElementById("statisticsChart"), {
            type: 'doughnut',
            data: {
              labels: stats,
              datasets: [
                {
                  label: "Statistics",
                  borderColor: "#112B44",
                  //                   assets    scans     doms       ips      svc       vulns
                  backgroundColor: ["#80FF00", "#5E29FF", "#266BEB", "#1CF3FF","#FFA516", "#FF073A", "#36FF74"],
                  data: values
                }
              ]
            },
            options: {
            tooltips: {
                            callbacks: {
                                labelTextColor: function(tooltipItem, chart) {
                                    return '#ffffffaa';
                                    }
                                }
                            },
            legend: { display: false },
            }
            });
          },
        renderHistory: function (){
            app.flushChart = !app.flushChart;
            axios.get('/pulsar/api/v1/scans/?ordering=scanned_date&status=SCANNED&format=json')
            .then(response => {
                app.scan_history.datasets = [];
                app.scan_history.labels = [];
                if (app.scan_history.datasets.length >= 0) {
                    response.data.forEach(function (scan){
                        asset_id = scan.asset.split('/')[7];
                        asset_name = app.assets.find(x => x.id == asset_id).name;
                        scan_dataset = app.scan_history.datasets.find(d => d.label === asset_name);
                        is_label = app.scan_history.labels.includes(new Date(scan.scanned_date))
                        color = app.randomColor();
                        if (!(is_label)){
                            app.scan_history.labels.push(new Date(scan.scanned_date))
                        }
                        if (!(scan_dataset)) {
                                app.scan_history.datasets.push({
                                    'label': asset_name,
                                    'data': [],
                                    fill: false,
                                    spanGaps: true,
                                    showLines: false,
                                    pointRadius: 3,
                                    borderWidth: 2,
                                    borderColor: color,
                                    backgroundColor: color,
                                    });
                                scan_index = app.scan_history.datasets.length-1;
                                app.scan_history.datasets[scan_index].data.push(
                                    {"x":new Date(scan.scanned_date), "y":scan.total_score.toFixed(2)}
                                )

                        } else {
                            scan_index = app.scan_history.datasets.indexOf(scan_dataset);
                            app.scan_history.datasets[scan_index].data.push({"x":new Date(scan.scanned_date), "y":scan.total_score.toFixed(2)});
                        }


                    });
                }

            }).then(() => {
                this.renderHistoryChart();
            })
        },
        renderHistoryChart: function() {
            Chart.defaults.line.spanGaps = true;
            var chart = document.getElementById("historyChart")
            if (chart && chart.className !== "chartjs-render-monitor") {
                new Chart(document.getElementById("historyChart"), {
                type: 'line',
                data: this.scan_history,
                options: {
                    tooltips: {
                        callbacks: {
                                labelTextColor: function(tooltipItem, chart) {
                                    return '#ffffffaa';
                                    }
                                },
                        mode: 'point'
                    },
                    legend: {
                        position: "bottom",
                        labels: {
                            fontColor: '#ffffffaa',
                        }
                    },
                    responsive: true,
                    aspectRatio: 5,
                    scales: {
                        yAxes:[{
                            ticks: {
                            beginAtZero: true,
                            suggestedMax: 10.0,
                            fontColor: "#ffffff66"
                            }
                        }],
                        xAxes: [{
                            type: 'time',
                            ticks: {fontColor: "#ffffff66"},
                            display: true,
                            time: {
                                unit: 'day',
                            },
                        }]
                    }
                }
                });
            }
          },
        randomColor: function(){
              var golden_ratio_conjugate = 0.618033988749895;
              var h = Math.random();

              var hslToRgb = function (h, s, l){
                  var r, g, b;

                  if(s == 0){
                      r = g = b = l;
                  }else{
                      function hue2rgb(p, q, t){
                          if(t < 0) t += 1;
                          if(t > 1) t -= 1;
                          if(t < 1/6) return p + (q - p) * 6 * t;
                          if(t < 1/2) return q;
                          if(t < 2/3) return p + (q - p) * (2/3 - t) * 6;
                          return p;
                      }

                      var q = l < 0.5 ? l * (1 + s) : l + s - l * s;
                      var p = 2 * l - q;
                      r = hue2rgb(p, q, h + 1/3);
                      g = hue2rgb(p, q, h);
                      b = hue2rgb(p, q, h - 1/3);
                  }

                  return '#'+Math.round(r * 255).toString(16)+Math.round(g * 255).toString(16)+Math.round(b * 255).toString(16);
              };
                h += golden_ratio_conjugate;
                h %= 1;
                return hslToRgb(h, 0.5, 0.60);
          },
        renderAssetChart: function() {
                var names = [];
                var scores = [];
                this.assets.slice(0,5).forEach(function (arrayItem) {
                    if (arrayItem.name.length > 10){
                        names.push(arrayItem.name.substring(0,10)+'...');
                    } else {
                        names.push(arrayItem.name);
                    }
                    scores.push(arrayItem.current_score);
                });
                var ctx = document.getElementById('assetChart').getContext('2d');
                var chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: names,
                        datasets: [{
                            label: 'Score',
                            maxBarLength: 10.0,
                            backgroundColor: "#FFA516",
                            borderColor: '#fff',
                            data: scores
                        }]
                    },

                    options: {
                        tooltips: {
                            callbacks: {
                                labelTextColor: function(tooltipItem, chart) {
                                    return '#ffffffaa';
                                    }
                                }
                            },
                        legend: { display: false },
                        scales: {
                            yAxes:[{
                            gridLines: {
                              display: false,
                            },
                            ticks: {beginAtZero: true, max: 10.0, fontColor: "#ffffff66"}}],
                            xAxes:[{
                            ticks: {fontColor: "#ffffff66"},
                            gridLines: {
                              display: false,
                            }
                            }]
                            },
                    }
                });
          },
        renderMap: function(dom_list, tag) {
              var clear =  document.getElementById(tag);
              clear.innerHTML = '';
              var countries = {};
              var domains = {};
              var incrementColor = function(color, step){
                var colorToInt = parseInt(color.substr(1), 16),
                    nstep = parseInt(step);
                if(!isNaN(colorToInt) && !isNaN(nstep)){
                    colorToInt += nstep;
                    var ncolor = colorToInt.toString(16);
                    ncolor = '#' + (new Array(7-ncolor.length).join(0)) + ncolor;
                    if(/^#[0-9a-f]{6}$/i.test(ncolor)){
                        return ncolor;
                    }
                }
                return color;
                };
              dom_list.forEach(function (arrayItem) {
                    if ( arrayItem.country in countries ){
                        if (countries[arrayItem.country] !== 65536*100) {
                            countries[arrayItem.country] = incrementColor(countries[arrayItem.country], 65536*20);
                            }
                        domains[arrayItem.country].domains++;
                    } else {
                        countries[arrayItem.country] = incrementColor("#1D5EB3", 65536*1);
                        domains[arrayItem.country] = {'domains':1};
                    }
                });

              var basic_choropleth = new Datamap({
              element: document.getElementById(tag),
              responsive: true,
              projection: 'mercator',
              fills: {
                defaultFill: "#212D3E",
                highScore: incrementColor("#1D5EB3", 65536*100)
              },
              data: domains,
              geographyConfig: {
                borderColor: '#141A26aa',
                highlightFillColor: "#123C73",
                highlightBorderColor: '#2986FF',
                popupTemplate: function(geo, data) {
                    return '<div style="font-size: small" class="ctooltip tooltip-inner">'+geo.properties.name+': '+data.domains+'</div>';
                    }
                }
            });

            var colors = d3.scale.category10();
            basic_choropleth.updateChoropleth(countries);

            window.addEventListener('resize', function(event){
            });
            app.world_loading = false;
            return basic_choropleth
        },
        filteredList: function() {
                return this.assets.filter(asset => {
                    if ( asset.name.toLowerCase().includes(this.search_query.toLowerCase()) ){
                        return true
                    } else {
                        return asset.domain.toLowerCase().includes(this.search_query.toLowerCase())
                    }
                })
            },
        cleanData: function (raw_data) {
              var data = raw_data;
              data.forEach(function (arrayItem) {
                // clean dates
                var c_string = (new Date(arrayItem.created_date)).toGMTString();
                var m_string = (new Date(arrayItem.modified_date)).toGMTString();
                data[data.indexOf(arrayItem)].created_date = c_string;
                data[data.indexOf(arrayItem)].modified_date = m_string;
                // clean scores
                var snum = arrayItem.current_score;
                if (snum >= 0){
                    data[data.indexOf(arrayItem)].current_score = snum.toFixed(2);
                } else {
                    data[data.indexOf(arrayItem)].current_score = 'N/A';
                }
                // upercase name
                var name = arrayItem.name.toUpperCase();
                data[data.indexOf(arrayItem)].name = name;
                //clear uid
                var id = arrayItem.id.split('/')[7];
                data[data.indexOf(arrayItem)].id = id;
                // schedule name
                var schname = arrayItem.schedule;
                if (schname === null){
                    data[data.indexOf(arrayItem)].schedule = 'NONE';
                } else {
                    data[data.indexOf(arrayItem)].schedule = schname.split('-')[6].toUpperCase();
                }

                });
              return data;
          },
        refreshAsset: function(id,name) {
            if (confirm('Do you really want to delete "'+name.toUpperCase()+'"?')){
                console.log('Deleting '+id);
            }

          },
        exportAsset: function(id, type) {
              var asset = {};
              if (type === 'pdf') {
                var pdf_data = '';
                axios.get('/pulsar/api/v1/assets/'+id+'/?format=json')
                  .then(response => {
                        asset = response.data;
                  }).then(() => {
                      axios.get('/pulsar/api/v1/assets/'+id+'/pdf?format=json')
                      .then(response => {
                            pdf_data = response.data.pdf;
                            let pdfContent = "data:application/pdf;base64," + pdf_data;
                              const data = encodeURI(pdfContent);
                              const link = document.createElement("a");
                              link.setAttribute("href", data);
                              let assetName = asset.name.toLowerCase().replace(/[\W_]+/g,"_");
                              let assetDate = (new Date(asset.modified_date)).getTime().toString();
                              link.setAttribute("download", assetName+"_"+assetDate+".pdf");
                              link.click();
                        });
                  });
              } else if (type === 'markdown') {
                var md_data = '';
                axios.get('/pulsar/api/v1/assets/'+id+'/?format=json')
                  .then(response => {
                        asset = response.data;
                  }).then(() => {
                      axios.get('/pulsar/api/v1/assets/'+id+'/markdown?format=json')
                      .then(response => {
                            md_data = response.data.markdown;
                            let mdContent = "data:application/octet-stream;charset=utf-16le;base64," + md_data;
                              const data = encodeURI(mdContent);
                              const link = document.createElement("a");
                              link.setAttribute("href", data);
                              let assetName = asset.name.toLowerCase().replace(/[\W_]+/g,"_");
                              let assetDate = (new Date(asset.modified_date)).getTime().toString();
                              link.setAttribute("download", assetName+"_"+assetDate+".md");
                              link.click();
                        });
                  });
              } else {
                  axios.get('/pulsar/api/v1/assets/'+id+'/?format=json')
                  .then(response => {
                        asset = response.data;
                        let jsonContent = "data:text/json;charset=utf-8,";
                          jsonContent += JSON.stringify(asset)
                          const data = encodeURI(jsonContent);
                          const link = document.createElement("a");
                          link.setAttribute("href", data);
                          let assetName = asset.name.toLowerCase().replace(/[\W_]+/g,"_");
                          let assetDate = (new Date(asset.modified_date)).getTime().toString();

                          link.setAttribute("download", assetName+"_"+assetDate+".json");
                          link.click();
                    });
              }
          },
        getCurrentDoms: function(){
            this.assets.forEach(function(asset){
                axios.get('/pulsar/api/v1/assets/'+asset.id+'/?format=json')
                    .then(response => {
                        response.data.doms.forEach(function (dom){
                            Vue.set(app.current_doms,app.current_doms.length++, dom);
                        });
                    });
            });

          },
        getEditName: function(){
            return this.edit_asset_name;
        },
        sendEditInfo: function(id, name) {
            this.edit_asset_id = id;
            this.edit_asset_name = name;
          },
        cancelCurrentScan: function(asset_id){
            axios.get('/pulsar/api/v1/scans/?status=UNSCANNED&format=json')
            .then(response => {
                response.data.forEach(function(scan){
                   if(scan.asset.includes(asset_id)){
                        axios.delete(scan.id, {headers:app.csrfToken()});
                        app.cancelScanTask(asset_id);
                   }
                });
            })

          },
        cancelScanTask: function(asset_id){
            app.active_progress.splice(app.active_progress.indexOf(asset_id), 1);
          },
        toBeScanned(id, name){
            app.scanAssetName = name;
            app.scanAssetId = id;
            var policy = {};
            var scans = [];
            axios.get('/pulsar/api/v1/assets/'+id+'/?format=json')
            .then(response => {
                scans = response.data.scans;
            }).then(() => {
                if (scans.length > 0){
                    axios.get(scans[0]).then(response =>{
                        app.scanSettingsData = response.data.policy;
                    });
                }
            })
        },
        makeLink: function (s,t){
            var new_one = true;
            this.net_data.links.forEach(function (link){
                if (link.source === s && link.target === t
                    || link.source === t && link.target === s){
                    new_one = false
                }
            })
            if (new_one) {
                this.net_data.links.push( { "source": s, "target": t } )
            }
          },
        objToArray: function (obj){
            var output = Object.entries(obj).map(([key, value]) => ({key,value}));
            return output
        },
        domsByAsset: function (asset_id){
            var dom_list = app.current_doms.filter(x => x.asset.includes("/pulsar/api/v1/assets/"
                +asset_id
                +"/?format=json"));
            app.asset_doms = dom_list;
        },
        deleteSchedule: function(asset_id){
            axios.get('/pulsar/api/v1/assets/'+asset_id+'/delete_schedule/');
        },
        getColor: function(score, tag){
            var color = d3.scale.linear()
              .domain([0.0, (0.0+10.0)/2, 10.0])
              .range(["lime", "yellow", "red"]);
            if (tag === 'b') {
                if (score >= 0.0){
                    return { 'color': 'black', 'backgroundColor': color(score) }
                } else {
                    return { 'color': 'var(--base2)', 'backgroundColor': 'var(--cool-gray)' }
                }
            } else if (tag === 'i') {
                if (score >= 0.0){
                    return { 'color': color(score) }
                } else {
                    return { 'color': 'var(--base2)' }
                }
            }

        },
        sortUnique: function(arr){
            if (arr.length === 0) return arr;
              arr = arr.sort(function (a, b) { return a*1 - b*1; });
              var ret = [arr[0]];
              for (var i = 1; i < arr.length; i++) {
                if (arr[i-1] !== arr[i]) {
                  ret.push(arr[i]);
                }
              }
            return ret;
        },
        getSvcs: function(ips){
            var port_list = {}
            var service_list = []
            ips.forEach(function(ip){
                if (ip.svcs.length > 0){
                    ip.svcs.forEach(function(s){
                        port_list[s.port] = [s.proto, s.desc]
                    })
                }
            })
            Object.keys(port_list).sort().forEach(function (port){
                service_list.push(
                    port_list[port][0].toUpperCase() + '/'+ port + ' ( ' + port_list[port][1] + ' ) '
                )
            })
            var sorted = this.sortUnique(service_list)
            if (sorted.length === 0){
                sorted = ['None']
            }
            return sorted
        },
        getCVSSLink: function(cvss){
            if (cvss.includes('/Au:') && !cvss.includes('/PR:')){
                link = 'https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=('+cvss+')'
            } else {
                link = 'https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=' + cvss
            }
            return link
        },
        cleanupCVSS: function(cvss){
            return cvss.replace('CVSS:3.0/','')
        },
        cleanupScore: function(score){
            if (score < 0){
                return 'N/A'
            } else {
            return score.toFixed(2)
            }
        }

  },
  mounted: function() {
  const STAR_DATA = generateStarData();

function createStar({x, y}, index, debug) {
  const starParallax = document.createElementNS("http://www.w3.org/2000/svg", 'g');
  starParallax.classList.add('star-parallax');

  const starTranslate = document.createElementNS("http://www.w3.org/2000/svg", 'g');
  starTranslate.setAttribute('transform', `translate(${x} ${y})`);

  const radius = debug ? 10 : 1;
  const depth = 1 + index%5;
  const parallaxIntensity = 200;
  const delay = index * 100 + 500 * Math.random();
  const duration = 3000 + Math.random() * 4000;
  const brightness = 0.7 + Math.random() * 0.3;

  starParallax.style.setProperty('--parallax-depth', depth);
  starParallax.style.setProperty('--parallax-intensity', parallaxIntensity);



  const star = document.createElementNS("http://www.w3.org/2000/svg", 'circle');
  star.setAttribute('r', radius);
  star.classList.add('star');

  star.style.setProperty('--star-animation-delay', `${delay}ms`);
  star.style.setProperty('--star-animation-duration', `${duration}ms`);
  star.style.setProperty('--star-animation-glow-duration', `10000ms`);
  star.style.setProperty('--star-brightness', `${brightness}`);

  starTranslate.appendChild(star);
  starParallax.appendChild(starTranslate);

  return starParallax;
}

function createNightSky({container, debug, starReference}) {
 STAR_DATA.forEach((data, index) => {
    const star = createStar(data, index, debug);
    container.appendChild(star);
 })
}

const starGroup = document.getElementById('starGroup');

createNightSky({container: starGroup, data: STAR_DATA});

function generateStarData() {
    var win = window,
    doc = document,
    docElem = doc.documentElement,
    body = doc.getElementsByTagName('body')[0],
    xs = win.innerWidth || docElem.clientWidth || body.clientWidth,
    ys = win.innerHeight|| docElem.clientHeight|| body.clientHeight;
    var stars = []
    for (i=0;i<100;i++){
        var s = {};
        s.x = Math.floor(Math.random()*xs);
        s.y = Math.floor(Math.random()*ys);
        stars.push(s);
    }
    return stars
};

  },
}).$mount('#app')

