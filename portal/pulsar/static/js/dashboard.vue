<template>
<div id="app">
    <div class="container pt-4">
        <div class="row pb-2" >
            <div class="col-lg-12">
                <div class="card-header">Discovery Map</div>
            </div>
        </div>
    </div>
    <div>
        <div class="full-width">
                <div class="card embed-responsive trans-map" id="world-canvas">
                    <div id="loader" v-if="app.world_loading" class="d-flex justify-content-center
                        net-map-container align-middle">
                        <b-spinner type="grow" label="Loading..."></b-spinner>
                    </div>
                    <div id="codez" class="card-body world-map pt-4" :key="app.flushChart">
                        <span class="typewriter code-left">
                            <pre v-for="(count, country) in app.getCountryStats()">{{country}}: {{count}}</pre>
                        </span>
                        <span class="typewriter code-right">
                            <pre v-for="asset in app.assets">{{app.truncate(asset.name,16)}}: {{asset.current_score}}</pre>
                        </span>
                        <div id="world_map"></div>
                    </div>
                    <div>
                </div>

        </div>
    </div>
    <div class="container pt-2">
        <div class="row pb-2" >
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Highest scores</div>
                    <div class="card-body" :key="app.flushChart">
                    <h6 class="card-subtitle mb-2 text-muted">Last 5 assets</h6>
                        <div id="loader" v-if="app.assets_loading"
                        class="d-flex justify-content-center net-map-container chart-loader align-middle">
                        <b-spinner type="grow" label="Loading..."></b-spinner>
                        </div>
                        <canvas v-show="!app.assets_loading" id="assetChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Application statistics</div>
                    <div class="card-body" :key="app.flushChart">
                        <h6 class="card-subtitle mb-2 text-muted">Database objects</h6>
                        <div id="loader" v-if="app.stats_loading"
                        class="d-flex justify-content-center net-map-container chart-loader align-middle">
                        <b-spinner type="grow" label="Loading..."></b-spinner>
                        </div>
                        <canvas v-show="!app.stats_loading" id="statisticsChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Most vulnerable</div>
                    <div class="card-body" :key="app.flushChart">
                        <h6 class="card-subtitle mb-2 text-muted">Top 5 domains</h6>
                        <div id="loader" v-if="app.top_loading"
                        class="d-flex justify-content-center net-map-container chart-loader align-middle">
                        <b-spinner type="grow" label="Loading..."></b-spinner>
                        </div>
                        <canvas  v-show="!app.top_loading" id="domainsChart"></canvas>
                    </div>
                    <!--
                    <div v-else class="card-body">
                        <h5 class="card-title">Most vulnerable</h5>
                        <div class="iplaceholder">∅</div>
                        <p class="card-subtitle mb-2 text-muted text-center">empty database</p>
                    </div>
                    -->
                </div>
            </div>
        </div>
    </div>
</div>
</template>
<script>
module.exports = {
    mounted: function() {
    app.world_loading = true;
    axios.get('/pulsar/api/v1/doms/active/?format=json')
          .then(response => {
                app.current_doms = response.data;
            }).then(() => {
                app.world_loading = false;
                app.top_loading = false;
                app.renderDomainsChart();
                app.renderMap(app.current_doms,'world_map');
            });
    axios.get('/pulsar/api/v1/assets/?format=json&ordering=-current_score')
          .then(response => {
            app.assets = app.cleanData(response.data);
            }).then(() => {
                app.assets_loading = false;
                app.renderAssetChart();
            })
    axios.get('/pulsar/api/v1/stats/?format=json')
          .then(response => {
                app.stats = response.data;
            }).then(() => {
                app.stats_loading = false;
                app.renderStatisticsChart();
            });
    },
}
</script>