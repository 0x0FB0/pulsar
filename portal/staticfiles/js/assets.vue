<template>
<div id="app">
    <div class="container pt-4">
        <div class="row pb-2" >
              <div class="col-lg-12">
              <div class="card-header">Assets History</div>
              </div>
        </div>
    </div>
    <div>
        <div class="full-width">
                <div class="card embed-responsive trans-map" id="chart-canvas">
                    <div class="col-7 hist pt-2" :key="app.flushChart">
                        <div id="loader" v-if="app.history_loading"
                            class="d-flex justify-content-center net-map-container align-middle">
                            <b-spinner type="grow" label="Loading..."></b-spinner>
                        </div>
                        <canvas id="historyChart" ></canvas>
                    </div>
                </div>
        </div>
    </div>
    <div class="container">
        <div class="row" >
              <div class="col-md-12">
            <div class="col-md-12 d-inline-flex pb-0">
            <b-button v-if="app.isActive()" v-b-modal.add-asset type="button"
                class="btn btn-success btn-sm mt-3 ml-2">
                 <i class="fas fa-plus-square"></i> Add
            </b-button>
            <b-button v-else v-b-modal.add-asset type="button"
                class="btn btn-success btn-sm blinking mt-4 ml-2">
                 <i class="fas fa-plus-square"></i> Add
            </b-button>
                <form class="form-inline col-sm-4 md-form form-sm active-pink-2 mt-3 ml-2">
                  <input class="form-control mr-2 w-75" type="text"
                   v-model="app.search_query" placeholder="Search" aria-label="Search">
                  <i class="fas fa-search" aria-hidden="true"></i>
                </form>
            </div>
            <div class="col table-wrapper-scroll card-body">
            <table class="table table-borderless table-hover table-responsive-xl">
              <thead class="th-override card-header">
                <tr class="header">
                  <th class="col-xs-2 text-center sortable " scope="col" v-for="asset in app.asset_columns" @click="app.sort(asset.key)">
                      {{ asset.name }}
                  </th>
                  <th class="col-xs-2 text-center" scope="col">Actions</th>
                </tr>
              </thead>

                <tbody id="assets-table">

                <tr v-for="(entry, index) in app.sortedAssets(app.filteredList())"  :key="entry.id" :data-index="index">
                  <td class="col-xs-2 align-middle filterable-cell text-center" v-for="asset in app.asset_columns">
                  <div v-if=" asset.key === 'created_date'" >
                  {{entry[asset.key]}}
                  </div>
                  <div v-else-if=" asset.key === 'schedule'" >
                      <h5>
                        <span class="badge badge-secondary nocolor"><strong>{{entry[asset.key]}}</strong></span>
                      </h5>
                  </div>
                  <div class="text-truncate" v-else-if="asset.key === 'name'" >
                  <strong>{{entry[asset.key]}}</strong>
                  <a v-b-modal.edit-asset user="'entry'" data-target="#edit-asset"
                          @mouseover="app.sendEditInfo(entry.id,entry.name)"
                          class="float-right mx-2" style="cursor: pointer">
                                <i class="fas fa-edit"></i>
                      </a>
                  </div>
                  <div class="current_score text-truncate" v-else-if="asset.key === 'current_score'" >
                  <div id="score" v-show="!app.active_progress.includes(entry.id)">
                  <h5>
                    <span class="badge badge-warning"
                    :style="app.getColor(entry[asset.key], 'b')">{{entry[asset.key]}}
                    </span>
                  </h5>
                  </div>
                  <div v-if="app.active_progress.includes(entry.id)" class="progress">
                      <div class="progress-bar progress-bar-striped progress-bar-animated"
                      role="progressbar" :style="'width: '+app.active_tasks[entry.id]+'%'"
                      :aria-valuenow="app.active_tasks[entry.id]" aria-valuemin="0" aria-valuemax="100"
                      v-if="app.active_progress.includes(entry.id)" >
                      </div>
                        <span class="mb-2">{{app.active_plugins[entry.id]}}</span>
                    </div>
                  </div>
                  <div v-else class="text-truncate">
                    {{entry[asset.key]}}
                  </td>
                  <td class="col-xs-2 align-middle filterable-cell text-center">
                    <div class="btn-toolbar-justified flex-wrap" role="toolbar">
                     <div class="btn-group mr-2 mt-1 ml-1" role="group" aria-label="Asset Actions">

                      <b-button v-show="app.active_progress.includes(entry.id)"
                      @click="app.cancelCurrentScan(entry.id)"
                      id="btn-info" class="btn btn-warning btn-sm"><i class="fas fa-stop"></i></b-button>

                      <b-button v-show="!app.active_progress.includes(entry.id)"
                       v-b-modal.scan-asset @mouseover="app.toBeScanned(entry.id, entry.name)" id="btn-info"
                      class="btn btn-warning btn-sm"><i class="fas fa-bolt mx-1"></i></b-button>

                      <div class="btn-group">
                      <b-button class="btn btn-sm btn-dark dropdown-toggle" type="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                      <i class="fas fa-download"></i>
                      </b-button>
                      <div class="dropdown-menu">
                        <a class="dropdown-item" href="#" @click="app.exportAsset(entry.id, 'json')">JSON</a>
                        <a class="dropdown-item" href="#" @click="app.exportAsset(entry.id, 'markdown')">MARKDOWN</a>
                        <a class="dropdown-item" href="#" @click="app.exportAsset(entry.id, 'pdf')">PDF</a>
                      </div>
                      </div>

                      <b-button v-b-modal.asset-map class="btn btn-dark btn-sm " type="button"
                        @mouseover="app.domsByAsset(entry.id)">
                        <i class="fas fa-globe"></i>
                      </b-button>

                      <div class="btn-group">
                      <b-button class="btn btn-sm btn-danger dropdown-toggle" type="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                      <i class="fas fa-trash-alt"></i>
                      </b-button>
                      <div class="dropdown-menu">
                        <a class="dropdown-item" href="#" @click="deleteAssetMsgBox(entry.id, entry.name)">Delete Asset</a>
                        <a class="dropdown-item" href="#" @click="app.deleteSchedule(entry.id)">Delete Schedule</a>
                      </div>
                      </div>
                     </div>
                    </div>
                    </td>
                </tr>
              </tbody>
            </table>
            </div>
        </div>
    </div>
    <b-modal
      centered
      ok-title="Add"
      id="add-asset"
      ref="modal"
      content-class="shadow"
      title="Create a new asset"
      @show="resetNewAssetModal"
      @hidden="resetNewAssetModal"
      @ok="handleNewAssetOk"
      @keydown.enter="handleNewAssetOk"
    >
      <form ref="form" @submit.stop.prevent="handleNewAssetSubmit" >
        <b-form-group
          :state="app.nameState"
          label="Name"
          label-for="name-input"
          invalid-feedback="Name is required"
        >
          <b-form-input
            id="name-input"
            v-model="app.add_asset_name"
            :state="app.nameState"
            placeholder="ACME INC"
            required
          ></b-form-input>
        </b-form-group>
        <b-form-group
          :state="app.nameState"
          label="Domain"
          label-for="name-input"
          invalid-feedback="Domain is required"
        >
          <b-form-input
            id="name-input"
            v-model="app.add_asset_domain"
            :state="app.nameState"
            placeholder="acme-inc.com"
            required
          ></b-form-input>
          <div class="mt-4" v-if="app.form_error.length > 0">
            {{app.form_error}}
          </div>
        </b-form-group>
      </form>
    </b-modal>

    <!-- NEW SCAN MODAL -->

    <b-modal
      centered
      ok-title="Scan"
      id="scan-asset"
      ref="modal"
      content-class="shadow"
      :title="'New scan for '+app.scanAssetName"
      @show="resetScanAssetModal"
      @hidden="resetScanAssetModal"
      @ok="handleScanAssetOk"
    >
      <form ref="form" @submit.stop.prevent="handleScanAssetSubmit" inline>
        <b-form-group
          :state="app.scanSettingsState"
          invalid-feedback="Please correct scan configuration"
        >
        <b-container fluid>
        <b-row>
          <b-col sm="10">
          <b-form-checkbox
            id="active-input"
            v-model="app.scanSettingsData['active']"
            :state="app.scanSettingsState"
            required
          >Active scan</b-form-checkbox>
          </b-col>
          <b-col sm="4" role="active">
          <b-form-select  size="sm"  v-if="app.scanSettingsData['active'] === true"
          v-model="app.scanSettingsData['top_ports']"
          :options="['5', '25', '50', '100', '1000']"
          >
          </b-form-select>
          </b-col>
          </b-row>
          <b-row>
          <b-col sm="10">
          <b-form-checkbox
            id="recursive-input"
            v-model="app.scanSettingsData['recursive']"
            :state="app.scanSettingsState"
            required>Recursive discovery</b-form-checkbox>
          </b-col>
          </b-row>
          <b-row>
          <b-col sm="10">
          <b-form-checkbox
            id="inscope-input"
            v-model="app.scanSettingsData['inscope']"
            :state="app.scanSettingsState"
            required >In-Scope discovery</b-form-checkbox>
          </b-col>
          </b-row>
          <b-row>
          <b-col sm="10" role="repeat">
          <b-form-checkbox
            id="repeat-input"
            v-model="app.scanSettingsData['repeat']"
            :state="app.scanSettingsState"
            required
          >Repeat scan</b-form-checkbox>
          </b-col>
          <b-col sm="4" role="repeat">
          <b-form-select  size="sm"  v-if="app.scanSettingsData['repeat'] === true"
          v-model="app.scanSettingsData['repeat_freq']"
          :options="['DAILY', 'WEEKLY', 'MONTHLY']"
          >
          </b-form-select>
          </b-col>
          </b-row>
          <b-row>
          <b-col sm="10">
          <b-form-checkbox
            id="notify-input"
            v-model="app.scanSettingsData['notify']"
            :state="app.scanSettingsState"
            required
          >Send notifications</b-form-checkbox>
          </b-col>
          </b-row>
          </b-container>
        </b-form-group>
      </form>
    </b-modal>


    <b-modal
      centered
      ok-title="Change"
      id="edit-asset"
      ref="modal"
      content-class="shadow"
      title="Rename asset"
      @show="resetEditAssetModal"
      @hidden="resetEditAssetModal"
      @ok="handleEditAssetOk"
    >
      <form ref="form" @submit.stop.prevent="handleEditAssetSubmit">
        <b-form-group
          :state="app.nameState"
          invalid-feedback="Name is required"
        >
          <b-form-input
            id="name-input"
            v-model="app.edit_asset_name"
            :state="app.nameState"
            required
          ></b-form-input>
        </b-form-group>
      </form>
    </b-modal>

     <b-modal
     id="asset-map"
     size="xl"
     content-class="shadow"
     ref="asset_map"
     static="true"
     @shown="app.renderMap(app.asset_doms,'asset_world_map')"
     hide-footer>
    <template v-slot:modal-title>
      Asset World Map
    </template>
    <div class="d-block card world-map-modal">
      <div  id="asset_world_map"></div>
    </div>
    <b-button class="mt-3" block @click="$bvModal.hide('asset-map')">Close</b-button>
    </b-modal>

</div>
</template>
<script>
module.exports = {
    methods: {
            checkAssetFormValidity() {
            const valid = this.$refs.form.checkValidity()
            app.nameState = valid ? 'valid' : 'invalid'
            if (valid && /^(?!:\/\/)([a-zA-Z0-9-]+\.){0,5}[a-zA-Z0-9-][a-zA-Z0-9-]+\.[a-zA-Z]{2,64}?$/gi.test(app.add_asset_domain)){
                return true
            } else {
                app.form_error="Resolvable, full domain name required.";
            }
          },
          checkEditFormValidity() {
            const valid = this.$refs.form.checkValidity()
            app.nameState = valid ? 'valid' : 'invalid'
            if (valid){
                return true
            } else {
                app.form_error="Asset name required.";
            }
          },
          checkScanFormValidity() {
            const valid = this.$refs.form.checkValidity()
            app.nameState = valid ? 'valid' : 'invalid'
            if (valid){
                return true
            } else {
                app.form_error="Please correct scan settings";
            }
          },
          resetNewAssetModal() {
            app.add_asset_name = '';
            app.add_asset_domain = '';
            app.form_error = '';
          },
          handleNewAssetOk(bvModalEvt) {
            // Prevent modal from closing
            bvModalEvt.preventDefault()
            // Trigger submit handler
            this.handleNewAssetSubmit()
            },
          handleNewAssetSubmit() {
            if (!this.checkAssetFormValidity()) {
              return
            }
            data={"name":app.add_asset_name, "domain":app.add_asset_domain}
            axios.post('/pulsar/api/v1/assets/',
            data,
            {headers:app.csrfToken()})
            .then(() => {
                axios.get('/pulsar/api/v1/assets/?format=json&ordering=-modified_date')
                  .then(response => {
                    app.assets = app.cleanData(response.data);
                    }).then(() => {
                        app.flushChart = !app.flushChart;
                        app.renderHistory();
                    })
            });
            this.$nextTick(() => {
              this.$refs.modal.hide()
            })

          },

          resetEditAssetModal() {
          },
          handleEditAssetOk(bvModalEvt) {
            bvModalEvt.preventDefault()
            this.handleEditAssetSubmit()
          },
          resetScanAssetModal() {

          },
          handleScanAssetOk(bvModalEvt) {
            bvModalEvt.preventDefault()
            this.handleScanAssetSubmit()
          },
          handleEditAssetSubmit() {
            if (!this.checkEditFormValidity()) {
              return
            }
            data={"name":app.edit_asset_name}
            axios.patch('/pulsar/api/v1/assets/'+app.edit_asset_id+'/?format=json',
            data,
            {headers:app.csrfToken()})
            .then(response => {
                axios.get('/pulsar/api/v1/assets/?format=json&ordering=-modified_date')
                  .then(response => {
                    app.assets = app.cleanData(response.data);
                    });
            });
            app.renderHistory();
            this.startUpdateTasks();
            this.$nextTick(() => {
              this.$refs.modal.hide()
            })
          },

          handleScanAssetSubmit() {
            if (!this.checkScanFormValidity()) {
              return
            }
            axios.get('/pulsar/api/v1/assets/'+app.scanAssetId+'/create_scan/?format=json',
                        {headers:app.csrfToken()})
                        .then(response => {
                            app.createdScan = response.data.id.split('?')[0];
                            })
                        .then(() => {
                            axios.patch(app.createdScan+'?format=json',
                            {'policy': app.scanSettingsData},
                            {headers:app.csrfToken()})
                            })
                        .then(() => {
                            axios.get(app.createdScan+'run/?format=json', {headers:app.csrfToken()})
                            })
                        .then(response => {
                                if (app.scan_updating === false){
                                    this.startUpdateTasks();
                                }
                            });

            this.$nextTick(() => {
              this.$refs.modal.hide()
            })
          },

          deleteAssetMsgBox(id, name) {
            app.delete_asset_confirmed = false;
            app.delete_asset_id = '';
            this.$bvModal.msgBoxConfirm('Do you want to delete "'+app.truncate(name,16)+'"?', {
              title: 'Delete asset',
              size: 'sm',
              buttonSize: 'sm',
              okVariant: 'danger',
              okTitle: 'YES',
              cancelTitle: 'NO',
              footerClass: 'p-2',
              hideHeaderClose: false,
              centered: true
            })
              .then(value => {
                if (value === true) {
                    axios.delete('/pulsar/api/v1/assets/'+id+'/', {headers:app.csrfToken()})
                    .then(response => {
                        const index = app.assets.findIndex(asset => asset.id === id);
                        if (~index){
                            app.assets.splice(index,1);
                        }
                    }).then(() => {
                        app.renderHistory();
                    })
                }
                })
              .catch(err => {
                console.log(err);
              }).then(() =>{
                app.renderHistoryChart();
              })
          },
          updateTasksStatus: function(){
            var current_tasks = [];
            axios.get('/pulsar/api/v1/tasks/active/?format=json')
                .then(response => {
                    response.data.forEach( function(task) {
                        if (task.hasOwnProperty('status') && task.status !== null && task.status.current !== 'None') {
                                task['asset'] = task['asset'].split('/')[7];
                                current_tasks.push(task.asset);
                                Vue.set(app.active_tasks, task.asset, task.status.percent);
                                Vue.set(app.active_plugins, task.asset, task.status.current);
                                index = app.active_progress.indexOf(task.asset);
                                if (index === -1){
                                    app.active_progress.push(task.asset);
                                } else {
                                    Vue.set(app.active_progress, index, task.asset);
                                }
                                if (!(task.asset in  app.active_tasks)){
                                    Vue.delete(app.active_tasks,task.asset);
                                    Vue.delete(app.active_plugins,task.asset);
                                    app.cancelScanTask(task.asset);
                                } else if (task.status.percent === 100){
                                    Vue.delete(app.active_tasks,task.asset);
                                    Vue.delete(app.active_plugins,task.asset);
                                    app.cancelScanTask(task.asset);
                                }
                            }

                    })
                    app.active_progress.forEach(function (asset){
                        index = current_tasks.indexOf(asset);
                        if (index === -1){
                            app.cancelScanTask(asset);
                        }
                    });
                    if (response.data.length === 0){
                       this.cancelUpdateTasks();
                       app.scan_updating = false;
                       for (key in app.active_tasks){
                         Vue.delete(app.active_tasks,key);
                         Vue.delete(app.active_plugins,key);
                         app.cancelScanTask(key.asset);
                       }
                       axios.get('/pulsar/api/v1/assets/?format=json&ordering=-modified_date')
                          .then(response => {
                            app.assets = app.cleanData(response.data);
                            })
                    }
                });



          },
          cancelUpdateTasks: function() {
          clearInterval(app.updateTasksTimer);
            app.history_loading = false;
            app.scan_updating = false;
            app.renderHistory();
           },
          startUpdateTasks: function() {
            app.updateTasksTimer = setInterval(this.updateTasksStatus, 1000)
          },

    },
    mounted: function() {
    app.history_loading = true;
    axios.get('/pulsar/api/v1/assets/?format=json&ordering=-modified_date')
          .then(response => {
            app.assets = app.cleanData(response.data);
            app.history_loading = false
            app.renderHistory();
            })

/*
    axios.get('/pulsar/api/v1/doms/active/?format=json')
          .then(response => {
            app.current_doms = response.data;
            }).then(() => {
            */
                axios.get('/pulsar/api/v1/tasks/active/?format=json')
                .then(response => {
                    if (response.data.length > 0 && !app.scan_updating && app.updateTasksTimer === ""){
                        this.startUpdateTasks();
                    }
                })

                /*
            })*/

    new function animate_assets(){
        const targetNode = document.getElementById('assets-table');
        const config = { attributes: false, childList: true, subtree: true };
        const callback = function(mutationsList, observer) {
            $( "#assets-table" ).hide().fadeIn(300);
        };
        const observer = new MutationObserver(callback);
        observer.observe(targetNode, config);
     }();
    },
}
</script>