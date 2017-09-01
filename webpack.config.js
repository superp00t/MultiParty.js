var webpack = require('webpack');
const path = require("path");
module.exports = {
    entry: './bundler.ts',
    output: {
        path: path.resolve(__dirname, './dist'),  
        filename: 'MultiParty.js',
        publicPath: '/'
    },
    resolve: {
        // Add `.ts` and `.tsx` as a resolvable extension.
        extensions: ['.webpack.js', '.web.js', '.ts', '.tsx', '.js']
    },
    module: {
        loaders: [
            // all files with a `.ts` or `.tsx` extension will be handled by `ts-loader`
            { test: /\.tsx?$/, loader: 'ts-loader' }
        ]
    },

    plugins: [
        // new webpack.DefinePlugin({
        //     'process.env': {
        //         NODE_ENV: JSON.stringify('production')
        //     }
        // }),
        // new webpack.optimize.UglifyJsPlugin({ output: {comments: false} })
    ]
}
