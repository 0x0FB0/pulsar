<template>
<div id="app">
    <div class="container pt-4">
        <div class="row  pb-2">
            <div class="col-lg-12">
                <div class="card-header">Network Map
                <a style="cursor: pointer; color: var(--base);" v-b-modal.fs-map class="float-right mb-2">
                        <i class="fas fa-arrows-alt"></i>
                    </a>
                </div>
            </div>
        </div>
    </div>
    <div>
        <div class="full-width" >
                <div class="card embed-responsive trans-map" >
                    <div id="loader" v-if="app.map_loading" class="d-flex justify-content-center net-map-container align-middle">
                        <b-spinner type="grow" label="Loading..."></b-spinner>
                    </div>
                    <div v-show="!app.map_loading" class="mind-map d-block" :key="app.flushChart" id="net-map-canvas" >
                    </div>

                </div>
        </div>
    </div>
    <div class="container pt-2">
        <div v-if="app.isActive()" class="card embed-responsive" id="chart-canvas">
            <div class="container">
              <div class="row pb-2  ">
              <div id="loader" v-if="app.table_loading" class="d-flex justify-content-center net-map-container align-middle">
                        <b-spinner type="grow" label="Loading..."></b-spinner>
                    </div>
                <div class="col nav-scroll nav-scrollbar">
                      <b-list-group v-for="asset in app.nested_data">
                        <b-list-group-item @click="app.objSelected = {'asset':asset}"
                            v-bind="app.table_loading = false"
                            v-b-toggle="asset.id.split('/')[7]" class="text-break" href="#">
                            <i class="far fa-building"
                            :style="app.getColor(asset.current_score, 'i')">
                            </i><strong class="pl-2 wrapped-name">{{asset.name.toUpperCase()}}</strong>
                            <b-badge variant="secondary nocolor" class="float-right" pill>{{asset.doms.length}}</b-badge>
                        </b-list-group-item>
                        <b-collapse :id="asset.id.split('/')[7]">
                            <template v-for="dom in asset.doms">
                                <b-list-group-item @click="app.objSelected = {'dom':dom}" :key="app.flushChart"
                                    v-b-toggle="dom.id.split('/')[7]" class="ml-1 text-break" href="#">
                                    <i class="fas fa-server"
                                    :style="app.getColor(dom.total_score, 'i')"></i>
                                    <strong class="pl-2 wrapped-name">{{dom.fqdn}}</strong>
                                    <b-badge variant="secondary nocolor" class="float-right" pill>
                                        {{dom.vulns.length}}
                                    </b-badge>
                                </b-list-group-item>
                                <b-collapse :id="dom.id.split('/')[7]">
                                    <template v-for="vuln in dom.vulns">
                                        <b-list-group-item
                                            @click="app.objSelected = {'vuln':vuln}"
                                            class="text-break ml-2" href="#">
                                            <i v-if="vuln.info" class="fas fa-info-circle"
                                            :style="{color: 'var(--base2)'}"></i>
                                            <i v-else class="fas fa-exclamation-triangle"
                                            :style="app.getColor(vuln.score, 'i')"></i>
                                            <strong class="pl-2 wrapped-name">{{vuln.name}}</strong>
                                        </b-list-group-item>
                                    </template>
                                </b-collapse>
                            </template>
                        </b-collapse>
                      </b-list-group>
                </div>
                <div class="col-8 nav-scroll nav-scrollbar">
                  <b-card-body :key="app.objRefresh">
                      <b-card-text class="custom-card-text" v-if="app.objSelected['vuln']">
                      <table v-if="!app.objSelected['vuln'].info"
                      class="table table-borderless table-hover table-sm table-responsive-sm">
                          <tr>
                            <td><strong>{{app.objSelected['vuln'].name}}</strong></td>
                            <td>

                                <b-button class="btn btn-standard btn-sm" type="button"
                                    @click="window.open(app.getCVSSLink(app.objSelected['vuln'].cvss), '_blank')">
                                    <strong>{{app.cleanupCVSS(app.objSelected['vuln'].cvss)}}</strong>
                                  </b-button>
                            </td>
                          <tr>
                          <tr>
                            <td>Score</td><td>
                            <h5><span class="badge badge-warning"
                            :style="app.getColor(app.objSelected['vuln'].score, 'b')">
                            {{app.objSelected['vuln'].score.toFixed(2)}}
                            </span></h5></td>
                          <tr>
                          <tr>
                            <td>Confidence</td><td>
                            <h5><span class="badge badge-secondary nocolor">
                            {{app.objSelected['vuln'].confidence.toFixed(2)}}
                            </span></h5></td>
                          <tr>
                          <tr>
                            <td>False Positive</td><td>
                              <label class="switch">
                                  <input type="checkbox" v-model="app.objSelected['vuln'].false_positive"
                                  @click="app.falsePositive(app.objSelected['vuln'].id,
                                    app.objSelected['vuln'].asset, !app.objSelected['vuln'].false_positive)">
                                  <span class="slider round"></span>
                                </label>
                            </td>
                          <tr>
                          <tr>
                            <td>Plugin</td><td>{{app.objSelected['vuln'].plugin}}</td>
                          <tr>
                          <tr>
                            <td>Discovery Date</td><td>{{new Date(app.objSelected['vuln'].found_date).toGMTString()}}</td>
                          <tr>
                          <tr><td>Issue Description</td><td>{{app.objSelected['vuln'].description}}</td></tr>
                          <tr>
                            <td>Details</td>
                            <td>
                                <b-button v-b-modal.vuln-poc class="btn btn-standard btn-sm " type="button"
                                    @mouseover="app.current_poc = app.objSelected['vuln'].details">
                                    <i class="fas fa-file-alt"></i>
                                  </b-button>
                            </td>
                          </tr>
                          <tr>
                            <td>Reference</td>
                            <td>
                                <a href="" @click="window.open(app.objSelected['vuln'].reference, '_blank')">
                                    {{app.objSelected['vuln'].reference}}
                                </a>
                            </td>
                          </tr>
                      </table>
                      <table v-else class="table table-borderless table-hover table-sm table-responsive-sm">
                          <tr>
                            <td><strong>{{app.objSelected['vuln'].name}}</strong></td>
                            <td>

                                <b-button class="btn btn-standard btn-sm" type="button"
                                    @click="window.open(app.getCVSSLink(app.objSelected['vuln'].cvss), '_blank')">
                                    <strong>{{app.cleanupCVSS(app.objSelected['vuln'].cvss)}}</strong>
                                  </b-button>
                            </td>
                          <tr>
                          <tr>
                            <td>Plugin</td><td>{{app.objSelected['vuln'].plugin}}</td>
                          <tr>
                          <tr>
                            <td>Discovery Date</td><td>{{new Date(app.objSelected['vuln'].found_date).toGMTString()}}</td>
                          <tr>
                          <tr><td>Issue Description</td><td>{{app.objSelected['vuln'].description}}</td></tr>
                          <tr>
                            <td>Details</td>
                            <td>
                                <b-button v-b-modal.vuln-poc class="btn btn-standard btn-sm " type="button"
                                    @mouseover="app.current_poc = app.objSelected['vuln'].details">
                                    <i class="fas fa-file-alt"></i>
                                  </b-button>
                            </td>
                          </tr>
                          <tr>
                            <td>Reference</td>
                            <td>
                                <a href="" @click="window.open(app.objSelected['vuln'].reference, '_blank')">
                                    {{app.objSelected['vuln'].reference}}
                                </a>
                            </td>
                          </tr>
                      </table>
                      </b-card-text>
                      <b-card-text class="custom-card-text" v-if="app.objSelected['dom']">
                      <table class="table table-borderless table-hover table-sm table-responsive-sm">
                          <tr>
                            <td>Fully Qualified Domain Name</td><td>{{app.objSelected['dom'].fqdn}}</td>
                          </tr>
                          <tr>
                            <td>IPv4 Address</td><td ><li v-for="ip in app.objSelected['dom'].ips">{{ip.ip}}</li></td>
                          </tr>
                          <tr>
                            <td>Services</td><td ><li v-for="svc in app.getSvcs(app.objSelected['dom'].ips)">
                                <span class="badge badge-secondary nocolor">{{svc}}</span>
                                </li>
                            </td>
                          </tr>
                          <tr>
                            <td>
                            Total Score</td><td>
                            <h5><span class="badge badge-warning"
                            :style="app.getColor(app.objSelected['dom'].total_score, 'b')">
                            {{app.objSelected['dom'].total_score.toFixed(2)}}
                            </span></h5></td>
                          </tr>
                          <tr>
                            <td>Confidence</td><td>
                            <h5><span class="badge badge-secondary nocolor">
                            {{app.objSelected['dom'].confidence.toFixed(2)}}
                            </span></h5></td>
                          </tr>
                          <tr>
                            <td>False positive</td><td>{{app.objSelected['dom'].false_postitive}}
                            <label class="switch">
                              <input type="checkbox" v-model="app.objSelected['dom'].false_positive"
                              @click="app.falsePositive(app.objSelected['dom'].id,
                                app.objSelected['dom'].asset, !app.objSelected['dom'].false_positive)">
                              <span class="slider round"></span>
                            </label>
                            </td>
                          </tr>
                          <tr>
                            <td>Country</td><td>{{app.objSelected['dom'].country}}</td>
                          </tr>
                          <tr>
                            <td>Plugin</td><td>{{app.objSelected['dom'].plugin}}</td>
                          </tr>
                          <tr>
                            <td>Discovery Date</td><td>{{new Date(app.objSelected['dom'].found_date).toGMTString()}}</td>
                          </tr>
                      </table>
                      </b-card-text>
                      <b-card-text class="custom-card-text" v-if="app.objSelected['asset']">
                      <table class="table table-borderless table-hover  table-sm table-responsive-sm">
                          <tr>
                            <td>Name</td><td><strong>{{app.objSelected['asset'].name.toUpperCase()}}<strong></td>
                          <tr>
                          <tr>
                            <td>Base Domain</td><td>{{app.objSelected['asset'].domain}}</td>
                          <tr>
                          <tr>
                            <td>Current Score</td><td>
                                <h5><span class="badge badge-warning"
                                :style="app.getColor(app.objSelected['asset'].current_score, 'b')">
                                {{app.cleanupScore(app.objSelected['asset'].current_score)}}
                                </span></h5></td>
                          <tr>
                          <tr>
                            <td>Created Date</td>
                            <td>{{new Date(app.objSelected['asset'].created_date).toGMTString()}}</td>
                          <tr>
                          <tr>
                            <td>Modified Date</td>
                            <td>{{new Date(app.objSelected['asset'].modified_date).toGMTString()}}</td>
                          <tr>
                      </table>
                      </b-card-text>
                    </b-card-body>
                </div>
              </div>
            </div>
        </div>
        <div v-else  class="card embed-responsive" id="net-map-canvas">
            <div class="card-body">
                <div class="iplaceholder"><i class="fas fa-exclamation"></i></div>
                <p class="card-subtitle mb-2 text-muted text-center">empty database</p>
            </div>
        </div>
    <div>
    <b-modal
     id="vuln-poc"
     size="xl"
     content-class="shadow"
     ref="asset_map"
     static="true"
     hide-footer>
    <template v-slot:modal-title>
      Plugin Details
    </template>
    <div class="d-block card-body text-break">
      <samp><pre>{{app.current_poc}}</pre></samp>
    </div>
    </b-modal>

    <b-modal
     id="fs-map"
     size="xl"
     content-class="shadow trans-map"
     class="full-screen"
     ref="fs-map"
     static="true"
     @shown="app.renderNetworkMapFull()"
     @close="app.renderNetworkMap()"
     hide-footer>
     <template v-slot:modal-title>
      Network Map
    </template>
    <div class="full-screen trans-map" id="fs-map-div">
      <div id="net-map-fullscreen">
      </div>
    </div>
    </b-modal>
</div>
</template>
<script>
module.exports = {
    methods: {
        toggle: function() {
          this.$emit("toggle", !this.isEnabled);
        },
    },
    mounted: function (){
        app.map_loading = true;
        app.table_loading = true;
        app.loadNetworkData();
        if (app.nested_data.length > 0){
            app.objSelected = {'asset':app.nested_data[0]}
        };
    },
}
</script>

